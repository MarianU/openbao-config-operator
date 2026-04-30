package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

const pkiCfgPath = "pki"

func TestPKIConfig_BaoName_TrimsSlashes(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"pki", "pki"},
		{"/pki", "pki"},
		{"pki/", "pki"},
		{"/pki/intermediate/", "pki/intermediate"},
	}
	for _, tc := range cases {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Path = tc.in
		require.Equal(t, tc.want, c.BaoName())
	}
}

func TestPKIConfig_OpenBaoNamespace_NormalizesWhitespace(t *testing.T) {
	t.Parallel()
	c := &OpenBaoPKISecretEngineConfig{}
	c.Spec.OpenBaoNamespace = "  acme/  "
	require.Equal(t, "acme/", c.OpenBaoNamespace())
}

// IsDeletable=false is load-bearing — it gates the shared base's
// BaoDelete call on CR delete, and the rename-cleanup path also
// skips BaoDeleteIdentity. Disabling a PKI mount destroys the
// private key irreversibly, so this MUST stay false.
func TestPKIConfig_IsDeletable_IsFalse(t *testing.T) {
	t.Parallel()
	c := &OpenBaoPKISecretEngineConfig{}
	require.False(t, c.IsDeletable(),
		"IsDeletable=false guards against destroying the CA's private key")
}

func TestPKIConfig_IsInitialized_IsTrue(t *testing.T) {
	t.Parallel()
	c := &OpenBaoPKISecretEngineConfig{}
	require.True(t, c.IsInitialized())
}

func TestPKIConfig_IsValid(t *testing.T) {
	t.Parallel()
	t.Run("happy path", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Path = pkiCfgPath
		c.Spec.PKIType = "root"
		c.Spec.CommonName = "Test CA"
		ok, err := c.IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})
	t.Run("empty path rejected", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.PKIType = "root"
		c.Spec.CommonName = "Test"
		ok, err := c.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "spec.path")
	})
	t.Run("empty commonName rejected", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Path = pkiCfgPath
		c.Spec.PKIType = "root"
		ok, err := c.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "spec.commonName")
	})
	t.Run("non-root pkiType rejected (intermediate not implemented)", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Path = pkiCfgPath
		c.Spec.PKIType = "intermediate"
		c.Spec.CommonName = "Test"
		ok, err := c.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "pkiType")
	})
}

func TestPKIConfig_IsEquivalentToDesiredState(t *testing.T) {
	t.Parallel()
	c := &OpenBaoPKISecretEngineConfig{}
	c.Spec.URLs = &PKIURLs{
		IssuingCertificates:   []string{"https://b.example.com/ca", "https://a.example.com/ca"},
		CRLDistributionPoints: []string{"https://example.com/crl"},
	}

	t.Run("caExists=false → drift (forces create path)", func(t *testing.T) {
		require.False(t, c.IsEquivalentToDesiredState(map[string]any{"caExists": false}))
	})

	t.Run("caExists=true + matching URLs → equivalent (slice order tolerated)", func(t *testing.T) {
		current := map[string]any{
			"caExists": true,
			"urls": map[string][]string{
				"issuingCertificates":   {"https://a.example.com/ca", "https://b.example.com/ca"},
				"crlDistributionPoints": {"https://example.com/crl"},
				"ocspServers":           nil,
			},
		}
		require.True(t, c.IsEquivalentToDesiredState(current))
	})

	t.Run("caExists=true + URL mismatch → drift", func(t *testing.T) {
		current := map[string]any{
			"caExists": true,
			"urls": map[string][]string{
				"issuingCertificates": {"https://wrong.example.com/ca"},
			},
		}
		require.False(t, c.IsEquivalentToDesiredState(current))
	})

	t.Run("nil URL fields on either side treated as empty", func(t *testing.T) {
		empty := &OpenBaoPKISecretEngineConfig{}
		current := map[string]any{
			"caExists": true,
			"urls":     map[string][]string{},
		}
		require.True(t, empty.IsEquivalentToDesiredState(current))
	})
}

func TestPKIConfig_MarkActive_SetsPhaseAndSerial(t *testing.T) {
	t.Parallel()
	c := &OpenBaoPKISecretEngineConfig{}
	require.Equal(t, "", c.Status.Phase)
	require.Equal(t, "", c.Status.CASerialNumber)

	c.MarkActive("ab:cd:ef")

	require.Equal(t, PhaseActive, c.Status.Phase)
	require.Equal(t, "ab:cd:ef", c.Status.CASerialNumber)
}

func TestPKIConfig_RenameTracker_RoundTrip(t *testing.T) {
	t.Parallel()
	c := &OpenBaoPKISecretEngineConfig{}
	require.Equal(t, "", c.LastWrittenBaoName())
	require.Equal(t, "", c.LastWrittenOpenBaoNamespace())
	c.SetLastWrittenBaoIdentity("pki", "acme/")
	require.Equal(t, "pki", c.LastWrittenBaoName())
	require.Equal(t, "acme/", c.LastWrittenOpenBaoNamespace())
}

func TestPKIConfig_PrepareInternalValues_NoOp(t *testing.T) {
	t.Parallel()
	c := &OpenBaoPKISecretEngineConfig{}
	require.NoError(t, c.PrepareInternalValues(context.Background(), c))
}
