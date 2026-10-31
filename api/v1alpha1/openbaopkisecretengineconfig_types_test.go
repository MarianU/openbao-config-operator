package v1alpha1

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

const (
	pkiCfgPath         = "pki"
	cnTest             = "Test"
	cnTestIntermediate = "Test Intermediate"
)

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

// PKIType defaults an empty spec.type to root (mirrors the CRD default for
// structs built outside the API server).
func TestPKIConfig_PKIType_DefaultsToRoot(t *testing.T) {
	t.Parallel()
	c := &OpenBaoPKISecretEngineConfig{}
	require.Equal(t, PKITypeRoot, c.PKIType())
	c.Spec.Type = PKITypeIntermediate
	require.Equal(t, PKITypeIntermediate, c.PKIType())
}

func TestPKIConfig_IsValid(t *testing.T) {
	t.Parallel()

	intRef := func(name string) *corev1.LocalObjectReference {
		return &corev1.LocalObjectReference{Name: name}
	}
	intSign := func(name string) *PKIInternalSign {
		return &PKIInternalSign{Name: name}
	}

	t.Run("root happy path", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Path = pkiCfgPath
		c.Spec.Type = PKITypeRoot
		c.Spec.CommonName = "Test CA"
		ok, err := c.IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})

	t.Run("empty type defaults to root and is valid", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Path = pkiCfgPath
		c.Spec.CommonName = "Test CA"
		ok, err := c.IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})

	t.Run("empty path rejected", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Type = PKITypeRoot
		c.Spec.CommonName = cnTest
		ok, err := c.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "spec.path")
	})

	t.Run("empty commonName rejected", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Path = pkiCfgPath
		c.Spec.Type = PKITypeRoot
		ok, err := c.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "spec.commonName")
	})

	t.Run("bogus type rejected", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Path = pkiCfgPath
		c.Spec.Type = "bogus"
		c.Spec.CommonName = cnTest
		ok, err := c.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "bogus")
	})

	t.Run("root rejects intermediate signing fields", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Path = pkiCfgPath
		c.Spec.Type = PKITypeRoot
		c.Spec.CommonName = cnTest
		c.Spec.InternalSign = intSign("pki-root")
		ok, err := c.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "intermediate")
	})

	t.Run("intermediate + internalSign ok", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Path = pkiCfgPath
		c.Spec.Type = PKITypeIntermediate
		c.Spec.CommonName = cnTestIntermediate
		c.Spec.InternalSign = intSign("pki-root")
		ok, err := c.IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})

	t.Run("intermediate + cross-namespace internalSign ok", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Path = pkiCfgPath
		c.Spec.Type = PKITypeIntermediate
		c.Spec.CommonName = cnTestIntermediate
		c.Spec.InternalSign = &PKIInternalSign{Name: "pki-platform", OpenBaoNamespace: "platform/"}
		ok, err := c.IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})

	t.Run("intermediate + externalSignSecret ok", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Path = pkiCfgPath
		c.Spec.Type = PKITypeIntermediate
		c.Spec.CommonName = cnTestIntermediate
		c.Spec.ExternalSignSecret = intRef("signed-ca")
		ok, err := c.IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})

	t.Run("intermediate + both signing models rejected", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Path = pkiCfgPath
		c.Spec.Type = PKITypeIntermediate
		c.Spec.CommonName = cnTestIntermediate
		c.Spec.InternalSign = intSign("pki-root")
		c.Spec.ExternalSignSecret = intRef("signed-ca")
		ok, err := c.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "exactly one")
	})

	t.Run("intermediate + neither signing model rejected", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Path = pkiCfgPath
		c.Spec.Type = PKITypeIntermediate
		c.Spec.CommonName = cnTestIntermediate
		ok, err := c.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "exactly one")
	})

	t.Run("intermediate + empty internalSign Name rejected", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.Path = pkiCfgPath
		c.Spec.Type = PKITypeIntermediate
		c.Spec.CommonName = cnTestIntermediate
		c.Spec.InternalSign = &PKIInternalSign{Name: ""}
		ok, err := c.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "exactly one")
	})
}

func TestPKIConfig_IsEquivalentToDesiredState(t *testing.T) {
	t.Parallel()
	c := &OpenBaoPKISecretEngineConfig{}
	c.Spec.IssuingCertificates = []string{"https://b.example.com/ca", "https://a.example.com/ca"}
	c.Spec.CRLDistributionPoints = []string{"https://example.com/crl"}

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

func TestPKIConfig_IsEquivalent_CABundlePublishDrift(t *testing.T) {
	t.Parallel()
	base := func() *OpenBaoPKISecretEngineConfig {
		c := &OpenBaoPKISecretEngineConfig{}
		c.Spec.PublishCABundleConfigMap = "team-a-ca"
		return c
	}
	payload := func(published string) map[string]any {
		return map[string]any{
			"caExists":          true,
			"caCert":            "PEM-A",
			"publishedCABundle": published,
			"urls":              map[string][]string{},
		}
	}

	t.Run("published matches active CA → equivalent", func(t *testing.T) {
		require.True(t, base().IsEquivalentToDesiredState(payload("PEM-A")))
	})
	t.Run("published missing → drift (forces publish)", func(t *testing.T) {
		require.False(t, base().IsEquivalentToDesiredState(payload("")))
	})
	t.Run("published stale → drift (forces republish)", func(t *testing.T) {
		require.False(t, base().IsEquivalentToDesiredState(payload("OLD-PEM")))
	})
	t.Run("publish not requested → bundle ignored", func(t *testing.T) {
		c := &OpenBaoPKISecretEngineConfig{} // no PublishCABundleConfigMap
		require.True(t, c.IsEquivalentToDesiredState(map[string]any{
			"caExists": true, "urls": map[string][]string{},
		}))
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
	// MarkActive does not stamp the intermediate-bootstrap booleans; those
	// are set by the controller's success mutator only for type=intermediate.
	require.False(t, c.Status.Generated)
	require.False(t, c.Status.Exported)
	require.False(t, c.Status.Signed)
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

// TestPKIConfig_CRLFieldJSONTag pins the spec JSON field name for
// CRLDistributionPoints to the lower-camelCase form so it stays consistent
// with issuingCertificates/ocspServers and the GetPayload key. A capital-C
// "CRLDistributionPoints" tag here previously produced a separate CRD field
// that silently pruned manifest-set crlDistributionPoints URLs.
func TestPKIConfig_CRLFieldJSONTag(t *testing.T) {
	t.Parallel()
	c := &OpenBaoPKISecretEngineConfig{}
	c.Spec.CRLDistributionPoints = []string{"https://example.com/crl"}
	b, err := json.Marshal(c)
	require.NoError(t, err)
	require.Contains(t, string(b), `"crlDistributionPoints"`)
	require.NotContains(t, string(b), `"CRLDistributionPoints"`)

	// Round-trip: a lower-camelCase field must unmarshal into Spec.
	round := OpenBaoPKISecretEngineConfig{}
	require.NoError(t, json.Unmarshal(b, &round))
	require.Equal(t, []string{"https://example.com/crl"}, round.Spec.CRLDistributionPoints)
}
