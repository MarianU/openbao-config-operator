package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenBaoConnection_IsValid(t *testing.T) {
	base := func(mut func(*OpenBaoConnection)) *OpenBaoConnection {
		c := &OpenBaoConnection{}
		c.Spec.Address = "https://bao.example:8200"
		c.Spec.Auth.Method = AuthMethodKubernetes
		c.Spec.Auth.Kubernetes = &OpenBaoKubernetesAuth{Role: "op"}
		mut(c)
		return c
	}

	ok, _ := base(func(*OpenBaoConnection) {}).IsValid()
	require.True(t, ok, "valid kubernetes-auth connection")

	_, err := base(func(c *OpenBaoConnection) { c.Spec.Address = "  " }).IsValid()
	require.Error(t, err, "empty address")

	_, err = base(func(c *OpenBaoConnection) { c.Spec.Auth.Method = AuthMethodToken }).IsValid()
	require.Error(t, err, "token method without token auth")

	_, err = base(func(c *OpenBaoConnection) { c.Spec.Auth.Method = "bogus" }).IsValid()
	require.Error(t, err, "unknown method")

	// kubernetes requires a non-empty role
	_, err = base(func(c *OpenBaoConnection) { c.Spec.Auth.Kubernetes.Role = "" }).IsValid()
	require.Error(t, err, "kubernetes auth without role")

	// token requires a secret ref name
	tok := base(func(c *OpenBaoConnection) {
		c.Spec.Auth.Method = AuthMethodToken
		c.Spec.Auth.Token = &OpenBaoTokenAuth{}
	})
	_, err = tok.IsValid()
	require.Error(t, err, "token method without tokenSecretRef")

	tok.Spec.Auth.Token.TokenSecretRef = SecretRef{Name: "bao-token"}
	ok, _ = tok.IsValid()
	require.True(t, ok, "valid token-auth connection")
}

func TestOpenBaoConnection_Defaulting(t *testing.T) {
	c := &OpenBaoConnection{}
	c.Spec.Auth.Kubernetes = &OpenBaoKubernetesAuth{Role: "r"}
	require.Equal(t, DefaultKubernetesAuthMount, c.Spec.AuthMount(), "default auth mount")
	require.Equal(t, DefaultJWTPath, c.Spec.AuthJWTPath(), "default jwt path")

	c.Spec.Auth.Kubernetes.Mount = "custom"
	c.Spec.Auth.Kubernetes.JWTPath = "/opt/token"
	require.Equal(t, "custom", c.Spec.AuthMount(), "custom auth mount")
	require.Equal(t, "/opt/token", c.Spec.AuthJWTPath(), "custom jwt path")
}

func TestOpenBaoConnection_ResolvedNamespace(t *testing.T) {
	c := &OpenBaoConnection{}
	c.Namespace = "ai"
	ref := &SecretRef{Name: "s"}
	require.Equal(t, "ai", c.ResolvedNamespace(ref), "defaults to connection namespace")
	ref2 := &SecretRef{Name: "s", Namespace: "vault"}
	require.Equal(t, "vault", c.ResolvedNamespace(ref2), "explicit namespace wins")
}

func TestOpenBaoConnection_ConnectionRefField(t *testing.T) {
	// Every primitive kind exposes ConnectionRef() so the engine can resolve
	// its connection. OpenBaoConnection itself is the connection (nil).
	p := &OpenBaoPolicy{}
	require.Nil(t, p.ConnectionRef(), "policy has no ref by default")
	p.Spec.ConnectionRef = &ConnectionRef{Name: "default"}
	require.Equal(t, "default", p.ConnectionRef().Name, "policy ref returned")
}
