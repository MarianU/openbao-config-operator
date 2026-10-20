package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	baoclient "github.com/stakater/openbao-config-operator/internal/client"
)

func ptrBool(b bool) *bool { return &b }
func ptrInt(i int) *int    { return &i }

func TestOpenBaoCertAuthEngineConfig_BaoName(t *testing.T) {
	t.Parallel()
	c := &OpenBaoCertAuthEngineConfig{}
	c.Spec.Path = "/cert/"
	require.Equal(t, "cert", c.BaoName())
}

func TestOpenBaoCertAuthEngineConfig_GetPath(t *testing.T) {
	t.Parallel()
	c := &OpenBaoCertAuthEngineConfig{}
	c.Spec.Path = sampleCertMount
	require.Equal(t, "auth/cert/config", c.GetPath())
}

func TestOpenBaoCertAuthEngineConfig_IsValid(t *testing.T) {
	t.Parallel()
	c := &OpenBaoCertAuthEngineConfig{}
	ok, err := c.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "spec.path")

	c.Spec.Path = sampleCertMount
	ok, err = c.IsValid()
	require.True(t, ok)
	require.NoError(t, err)
}

// IsDeletable is false: bao has no DELETE on auth/<mount>/config.
func TestOpenBaoCertAuthEngineConfig_IsDeletable(t *testing.T) {
	t.Parallel()
	c := &OpenBaoCertAuthEngineConfig{}
	require.False(t, c.IsDeletable(),
		"cert auth config has no DELETE endpoint; CR delete must release the finalizer without touching bao")
}

// Drift comparator: nil-on-spec means "adopt bao's value" (no drift).
func TestOpenBaoCertAuthEngineConfig_IsEquivalent_AdoptsBaoForUnpinned(t *testing.T) {
	t.Parallel()
	c := &OpenBaoCertAuthEngineConfig{}
	c.Spec.Path = sampleCertMount
	// Spec leaves all fields nil → must be equivalent to whatever bao echoes.
	cur := &baoclient.CertAuthConfigSpec{
		DisableBinding:              ptrBool(false),
		EnableIdentityAliasMetadata: ptrBool(true),
		OCSPCacheSize:               ptrInt(100),
	}
	require.True(t, c.IsEquivalentToDesiredState(map[string]any{"config": cur}))
}

func TestOpenBaoCertAuthEngineConfig_IsEquivalent_DriftOnPinnedField(t *testing.T) {
	t.Parallel()
	c := &OpenBaoCertAuthEngineConfig{}
	c.Spec.Path = sampleCertMount
	c.Spec.OCSPCacheSize = ptrInt(500)

	cur := &baoclient.CertAuthConfigSpec{OCSPCacheSize: ptrInt(100)}
	require.False(t, c.IsEquivalentToDesiredState(map[string]any{"config": cur}))

	cur.OCSPCacheSize = ptrInt(500)
	require.True(t, c.IsEquivalentToDesiredState(map[string]any{"config": cur}))
}

func TestOpenBaoCertAuthEngineConfig_ToBaoSpec_PassthroughPointers(t *testing.T) {
	t.Parallel()
	c := &OpenBaoCertAuthEngineConfig{}
	c.Spec.Path = sampleCertMount
	c.Spec.DisableBinding = ptrBool(true)
	c.Spec.OCSPCacheSize = ptrInt(200)

	spec := c.ToBaoSpec()
	require.NotNil(t, spec.DisableBinding)
	require.True(t, *spec.DisableBinding)
	require.NotNil(t, spec.OCSPCacheSize)
	require.Equal(t, 200, *spec.OCSPCacheSize)
	require.Nil(t, spec.OCSPFailOpen, "unset spec field passes through as nil")
}

func TestOpenBaoCertAuthEngineConfig_PrepareInternalValues_NoOp(t *testing.T) {
	t.Parallel()
	c := &OpenBaoCertAuthEngineConfig{}
	require.NoError(t, c.PrepareInternalValues(context.Background(), c))
}
