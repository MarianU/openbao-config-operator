package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	baoclient "github.com/stakater-ab/openbao-config-operator/internal/client"
)

const (
	sampleK8sAuthMount = "kubernetes"
	sampleK8sAuthHost  = "https://kubernetes.default.svc:443"
	sampleK8sJWT       = "eyJ.fake.jwt"
	sampleK8sCA        = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
)

func TestOpenBaoKubernetesAuthEngineConfig_BaoName(t *testing.T) {
	t.Parallel()
	c := &OpenBaoKubernetesAuthEngineConfig{}
	c.Spec.Path = "/kubernetes/"
	require.Equal(t, "kubernetes", c.BaoName())
}

func TestOpenBaoKubernetesAuthEngineConfig_OpenBaoNamespace_Trims(t *testing.T) {
	t.Parallel()
	c := &OpenBaoKubernetesAuthEngineConfig{}
	c.Spec.OpenBaoNamespace = "  team-a/  "
	require.Equal(t, "team-a/", c.OpenBaoNamespace())
}

func TestOpenBaoKubernetesAuthEngineConfig_GetPath(t *testing.T) {
	t.Parallel()
	c := &OpenBaoKubernetesAuthEngineConfig{}
	c.Spec.Path = sampleK8sAuthMount
	require.Equal(t, "auth/kubernetes/config", c.GetPath())
}

func TestOpenBaoKubernetesAuthEngineConfig_IsValid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mutate  func(c *OpenBaoKubernetesAuthEngineConfig)
		wantErr string
	}{
		{
			name:    "empty-path",
			mutate:  func(c *OpenBaoKubernetesAuthEngineConfig) { c.Spec.Path = "" },
			wantErr: "spec.path",
		},
		{
			name:    "empty-host",
			mutate:  func(c *OpenBaoKubernetesAuthEngineConfig) { c.Spec.KubernetesHost = "" },
			wantErr: "spec.kubernetesHost",
		},
		{
			name: "empty-jwt-ref-name",
			mutate: func(c *OpenBaoKubernetesAuthEngineConfig) {
				c.Spec.TokenReviewerJwtRef = &KubernetesTokenReviewerSecretRef{Name: ""}
			},
			wantErr: "spec.tokenReviewerJwtRef.name",
		},
		{
			name: "empty-ca-ref-name",
			mutate: func(c *OpenBaoKubernetesAuthEngineConfig) {
				c.Spec.KubernetesCaCertRef = &KubernetesCaSecretRef{Name: ""}
			},
			wantErr: "spec.kubernetesCaCertRef.name",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := validK8sAuthConfig()
			tc.mutate(c)
			ok, err := c.IsValid()
			require.False(t, ok)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}

	t.Run("valid-baseline", func(t *testing.T) {
		t.Parallel()
		c := validK8sAuthConfig()
		ok, err := c.IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})
}

// IsDeletable is false: bao has no DELETE on auth/<mount>/config.
func TestOpenBaoKubernetesAuthEngineConfig_IsDeletable(t *testing.T) {
	t.Parallel()
	c := &OpenBaoKubernetesAuthEngineConfig{}
	require.False(t, c.IsDeletable(),
		"kubernetes auth config has no DELETE endpoint; CR delete must release the finalizer without touching bao")
}

// Drift comparator: empty desired adopts bao's value (no drift).
func TestOpenBaoKubernetesAuthEngineConfig_IsEquivalent_AdoptsBaoForUnpinned(t *testing.T) {
	t.Parallel()
	c := validK8sAuthConfig()
	c.Spec.Issuer = "" // unpin issuer
	cur := &baoclient.K8sAuthConfigSpec{
		KubernetesHost:       sampleK8sAuthHost,
		Issuer:               "kubernetes/serviceaccount",
		DisableISSValidation: ptrBool(false),
	}
	require.True(t, c.IsEquivalentToDesiredState(map[string]interface{}{"config": cur}))
}

func TestOpenBaoKubernetesAuthEngineConfig_IsEquivalent_DriftsOnHost(t *testing.T) {
	t.Parallel()
	c := validK8sAuthConfig()
	cur := &baoclient.K8sAuthConfigSpec{
		KubernetesHost: "https://other.example.com:6443",
	}
	require.False(t, c.IsEquivalentToDesiredState(map[string]interface{}{"config": cur}))
}

// PEMKeys order must not cause spurious drift.
func TestOpenBaoKubernetesAuthEngineConfig_IsEquivalent_PEMKeysOrderInsensitive(t *testing.T) {
	t.Parallel()
	c := validK8sAuthConfig()
	c.Spec.PEMKeys = []string{"key-a", "key-b"}
	cur := &baoclient.K8sAuthConfigSpec{
		KubernetesHost: sampleK8sAuthHost,
		PEMKeys:        []string{"key-b", "key-a"},
	}
	require.True(t, c.IsEquivalentToDesiredState(map[string]interface{}{"config": cur}))
}

// MAC-based rotation detection: when the resolved Secret's MAC
// matches the last-written MAC, no drift even if bao redacts the JWT.
func TestOpenBaoKubernetesAuthEngineConfig_IsEquivalent_MACMatch_NoDrift(t *testing.T) {
	t.Parallel()
	c := validK8sAuthConfig()
	cur := &baoclient.K8sAuthConfigSpec{
		KubernetesHost:   sampleK8sAuthHost,
		TokenReviewerJWT: "", // bao redacts
	}
	require.True(t, c.IsEquivalentToDesiredState(map[string]interface{}{
		"config":               cur,
		"currentSecretMAC":     "abc",
		"lastWrittenSecretMAC": "abc",
	}))
}

// MAC-based rotation detection: when the resolved Secret's MAC differs
// from the last-written MAC, drift is reported even though bao redacts
// the JWT. This is the rotation case that previously slipped through.
func TestOpenBaoKubernetesAuthEngineConfig_IsEquivalent_MACMismatch_Drifts(t *testing.T) {
	t.Parallel()
	c := validK8sAuthConfig()
	cur := &baoclient.K8sAuthConfigSpec{
		KubernetesHost:   sampleK8sAuthHost,
		TokenReviewerJWT: "", // bao redacts
	}
	require.False(t, c.IsEquivalentToDesiredState(map[string]interface{}{
		"config":               cur,
		"currentSecretMAC":     "rotated",
		"lastWrittenSecretMAC": "old",
	}))
}

// SecretMACInputs returns the resolved values in the documented order;
// changes to either input must change the MAC.
func TestOpenBaoKubernetesAuthEngineConfig_SecretMACInputs_OrderAndContent(t *testing.T) {
	t.Parallel()
	c := validK8sAuthConfig()
	c.Status.ResolvedTokenReviewerJWT = sampleK8sJWT
	c.Status.ResolvedKubernetesCACert = sampleK8sCA
	inputs := c.SecretMACInputs()
	require.Len(t, inputs, 2)
	require.Equal(t, sampleK8sJWT, string(inputs[0]))
	require.Equal(t, sampleK8sCA, string(inputs[1]))
}

// PrepareInternalValues resolves Secret refs into status fields.
func TestOpenBaoKubernetesAuthEngineConfig_PrepareInternalValues_ResolvesSecrets(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	jwtSec := &corev1.Secret{}
	jwtSec.Name = "k8s-token"
	jwtSec.Namespace = sampleAliasNS
	jwtSec.Data = map[string][]byte{"token": []byte(sampleK8sJWT)}
	caSec := &corev1.Secret{}
	caSec.Name = "k8s-ca"
	caSec.Namespace = sampleAliasNS
	caSec.Data = map[string][]byte{"ca.crt": []byte(sampleK8sCA)}

	cl := crfake.NewClientBuilder().WithScheme(scheme).WithObjects(jwtSec, caSec).Build()
	c := validK8sAuthConfig()
	c.Spec.TokenReviewerJwtRef = &KubernetesTokenReviewerSecretRef{Name: "k8s-token"}
	c.Spec.KubernetesCaCertRef = &KubernetesCaSecretRef{Name: "k8s-ca"}

	//nolint:staticcheck // matches PrepareInternalValues contract
	ctx := context.WithValue(context.Background(), "kubeClient", cl)
	require.NoError(t, c.PrepareInternalValues(ctx, c))
	require.Equal(t, sampleK8sJWT, c.Status.ResolvedTokenReviewerJWT)
	require.Equal(t, sampleK8sCA, c.Status.ResolvedKubernetesCACert)
}

// PrepareInternalValues without any refs is a no-op (no kube client
// required). Mirrors JWT/OIDC config's empty-ref short-circuit.
func TestOpenBaoKubernetesAuthEngineConfig_PrepareInternalValues_EmptyRefsNoop(t *testing.T) {
	t.Parallel()
	c := validK8sAuthConfig()
	require.NoError(t, c.PrepareInternalValues(context.Background(), c))
	require.Empty(t, c.Status.ResolvedTokenReviewerJWT)
	require.Empty(t, c.Status.ResolvedKubernetesCACert)
}

func TestOpenBaoKubernetesAuthEngineConfig_ToBaoSpec_CarriesResolvedValues(t *testing.T) {
	t.Parallel()
	c := validK8sAuthConfig()
	c.Status.ResolvedTokenReviewerJWT = sampleK8sJWT
	c.Status.ResolvedKubernetesCACert = sampleK8sCA
	out := c.ToBaoSpec()
	require.Equal(t, sampleK8sJWT, out.TokenReviewerJWT)
	require.Equal(t, sampleK8sCA, out.KubernetesCACert)
	require.Equal(t, sampleK8sAuthHost, out.KubernetesHost)
}

func validK8sAuthConfig() *OpenBaoKubernetesAuthEngineConfig {
	c := &OpenBaoKubernetesAuthEngineConfig{}
	c.Name = sampleK8sAuthMount
	c.Namespace = sampleAliasNS
	c.Spec.Path = sampleK8sAuthMount
	c.Spec.KubernetesHost = sampleK8sAuthHost
	return c
}
