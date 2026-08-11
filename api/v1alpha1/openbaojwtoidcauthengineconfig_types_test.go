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
	jwtMount        = "oidc"
	jwtClientSecret = "shhhh"
)

func newJWTConfig() *OpenBaoJWTOIDCAuthEngineConfig {
	c := &OpenBaoJWTOIDCAuthEngineConfig{}
	c.Namespace = sampleAliasNS
	c.Name = jwtMount
	c.Spec.Path = jwtMount
	c.Spec.OIDCDiscoveryURL = "https://accounts.example.com"
	return c
}

func TestOpenBaoJWTOIDCAuthEngineConfig_GetPath(t *testing.T) {
	t.Parallel()
	c := newJWTConfig()
	require.Equal(t, "auth/oidc/config", c.GetPath())
}

func TestOpenBaoJWTOIDCAuthEngineConfig_IsDeletableFalse(t *testing.T) {
	t.Parallel()
	c := newJWTConfig()
	require.False(t, c.IsDeletable())
}

func TestOpenBaoJWTOIDCAuthEngineConfig_IsValid(t *testing.T) {
	t.Parallel()
	c := newJWTConfig()
	ok, err := c.IsValid()
	require.True(t, ok)
	require.NoError(t, err)

	// Empty path → reject.
	c2 := newJWTConfig()
	c2.Spec.Path = ""
	ok, err = c2.IsValid()
	require.False(t, ok)
	require.Error(t, err)

	// No way to validate inbound tokens → reject.
	c3 := newJWTConfig()
	c3.Spec.OIDCDiscoveryURL = ""
	ok, err = c3.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "validate inbound tokens")

	// JWKsURL alone is enough.
	c4 := newJWTConfig()
	c4.Spec.OIDCDiscoveryURL = ""
	c4.Spec.JWKsURL = "https://example.com/jwks"
	ok, err = c4.IsValid()
	require.True(t, ok)
	require.NoError(t, err)

	// Static pubkeys alone is enough.
	c5 := newJWTConfig()
	c5.Spec.OIDCDiscoveryURL = ""
	c5.Spec.JWTValidationPubkeys = []string{"-----BEGIN PUBLIC KEY-----..."}
	ok, err = c5.IsValid()
	require.True(t, ok)
	require.NoError(t, err)
}

func TestOpenBaoJWTOIDCAuthEngineConfig_PrepareInternalValues_ResolvesSecret(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, AddToScheme(scheme))

	sec := &corev1.Secret{}
	sec.Name = "oidc-client"
	sec.Namespace = sampleAliasNS
	sec.Data = map[string][]byte{"oidcClientSecret": []byte(jwtClientSecret)}

	cl := crfake.NewClientBuilder().WithScheme(scheme).WithObjects(sec).Build()

	c := newJWTConfig()
	c.Spec.OIDCClientSecretRef = &OIDCClientSecretRef{Name: "oidc-client"}
	//nolint:staticcheck // matches the shared base contract
	ctx := context.WithValue(context.Background(), "kubeClient", cl)
	require.NoError(t, c.PrepareInternalValues(ctx, c))
	require.Equal(t, jwtClientSecret, c.Status.ResolvedClientSecret)
}

func TestOpenBaoJWTOIDCAuthEngineConfig_PrepareInternalValues_NoRef(t *testing.T) {
	t.Parallel()
	c := newJWTConfig()
	c.Status.ResolvedClientSecret = "old"
	require.NoError(t, c.PrepareInternalValues(context.Background(), c))
	require.Empty(t, c.Status.ResolvedClientSecret,
		"empty ref must clear any stale resolved value")
}

func TestOpenBaoJWTOIDCAuthEngineConfig_PrepareInternalValues_MissingSecret(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, AddToScheme(scheme))
	cl := crfake.NewClientBuilder().WithScheme(scheme).Build()

	c := newJWTConfig()
	c.Spec.OIDCClientSecretRef = &OIDCClientSecretRef{Name: "missing"}
	//nolint:staticcheck // matches the shared base contract
	ctx := context.WithValue(context.Background(), "kubeClient", cl)
	require.Error(t, c.PrepareInternalValues(ctx, c))
}

// Drift comparator: empty desired adopts bao value (no drift); pinned
// fields drive drift on diff.
func TestOpenBaoJWTOIDCAuthEngineConfig_IsEquivalent(t *testing.T) {
	t.Parallel()
	c := newJWTConfig()
	cur := &baoclient.JWTOIDCConfigSpec{OIDCDiscoveryURL: "https://accounts.example.com"}
	require.True(t, c.IsEquivalentToDesiredState(map[string]any{"config": cur}))

	cur.OIDCDiscoveryURL = "https://other.example.com"
	require.False(t, c.IsEquivalentToDesiredState(map[string]any{"config": cur}))
}

func TestOpenBaoJWTOIDCAuthEngineConfig_ToBaoSpec_CarriesResolvedSecret(t *testing.T) {
	t.Parallel()
	c := newJWTConfig()
	c.Spec.OIDCClientID = "bao-client"
	c.Status.ResolvedClientSecret = jwtClientSecret
	spec := c.ToBaoSpec()
	require.Equal(t, "bao-client", spec.OIDCClientID)
	require.Equal(t, jwtClientSecret, spec.OIDCClientSecret)
}

// HMAC-pattern upgrade path: a CR that was last reconciled by a
// pre-MAC operator has Status.LastWrittenSecretMAC == "". The new
// operator's first reconcile must treat that as drift (empty != freshly
// computed MAC) so a write fires and stamps the MAC, putting the CR
// back on the steady-state path. Locks in the migration story for
// already-deployed CRs.
func TestOpenBaoJWTOIDCAuthEngineConfig_IsEquivalent_EmptyLastMAC_TreatedAsDrift(t *testing.T) {
	t.Parallel()
	c := newJWTConfig()
	cur := &baoclient.JWTOIDCConfigSpec{OIDCDiscoveryURL: "https://accounts.example.com"}
	// All non-MAC fields match (no other drift), but lastWrittenSecretMAC
	// is empty (upgrade case) and currentSecretMAC is computed from a
	// resolved Secret — they differ, comparator must report drift.
	require.False(t, c.IsEquivalentToDesiredState(map[string]interface{}{
		"config":               cur,
		"currentSecretMAC":     "some-computed-mac",
		"lastWrittenSecretMAC": "",
	}))
}

// MAC-equality fast path: when both currentSecretMAC and
// lastWrittenSecretMAC are empty (no Secret-sourced field on this CR
// at all), the comparator must NOT spuriously report drift on the
// MAC line.
func TestOpenBaoJWTOIDCAuthEngineConfig_IsEquivalent_BothMACsEmpty_NoDrift(t *testing.T) {
	t.Parallel()
	c := newJWTConfig()
	cur := &baoclient.JWTOIDCConfigSpec{OIDCDiscoveryURL: "https://accounts.example.com"}
	require.True(t, c.IsEquivalentToDesiredState(map[string]interface{}{
		"config":               cur,
		"currentSecretMAC":     "",
		"lastWrittenSecretMAC": "",
	}))
}
