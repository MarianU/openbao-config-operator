package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	baoclient "github.com/stakater/openbao-config-operator/internal/client"
)

const pkiRoleMount = "pki"

func TestPKIRole_BaoName_PrefersSpecNameAndLowerTrims(t *testing.T) {
	t.Parallel()
	t.Run("spec.name wins over metadata.name", func(t *testing.T) {
		r := &OpenBaoPKISecretEngineRole{}
		r.Name = "metadata-name"
		r.Spec.Name = "spec-name"
		require.Equal(t, "spec-name", r.BaoName())
	})
	t.Run("metadata.name fallback when spec.name empty", func(t *testing.T) {
		r := &OpenBaoPKISecretEngineRole{}
		r.Name = "fallback"
		require.Equal(t, "fallback", r.BaoName())
	})
	t.Run("normalization", func(t *testing.T) {
		r := &OpenBaoPKISecretEngineRole{}
		r.Spec.Name = "  Mixed-Case  "
		require.Equal(t, "mixed-case", r.BaoName())
	})
}

// Default deletability is the inverse of PKIConfig — deleting a role is
// safe (no key material); the bao role is just an issuance gate.
func TestPKIRole_IsDeletable_IsTrue(t *testing.T) {
	t.Parallel()
	r := &OpenBaoPKISecretEngineRole{}
	require.True(t, r.IsDeletable())
}

func TestPKIRole_GetPath_IncludesMountAndName(t *testing.T) {
	t.Parallel()
	r := &OpenBaoPKISecretEngineRole{}
	r.Name = "web-server"
	r.Spec.Path = pkiRoleMount
	require.Equal(t, "pki/roles/web-server", r.GetPath())
}

func TestPKIRole_IsValid(t *testing.T) {
	t.Parallel()
	t.Run("happy path with allowedDomains", func(t *testing.T) {
		r := &OpenBaoPKISecretEngineRole{}
		r.Spec.Path = pkiRoleMount
		r.Spec.AllowedDomains = []string{"example.com"}
		ok, err := r.IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})
	t.Run("happy path with allowAnyName", func(t *testing.T) {
		r := &OpenBaoPKISecretEngineRole{}
		r.Spec.Path = pkiRoleMount
		r.Spec.AllowAnyName = true
		ok, err := r.IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})
	t.Run("empty path rejected", func(t *testing.T) {
		r := &OpenBaoPKISecretEngineRole{}
		r.Spec.AllowAnyName = true
		ok, err := r.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "spec.path")
	})
	t.Run("no allow* — issuance impossible, rejected", func(t *testing.T) {
		r := &OpenBaoPKISecretEngineRole{}
		r.Spec.Path = pkiRoleMount
		ok, err := r.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "allowAnyName")
	})
}

func TestPKIRole_IsEquivalentToDesiredState(t *testing.T) {
	t.Parallel()
	r := &OpenBaoPKISecretEngineRole{}
	r.Spec.AllowedDomains = []string{"b.example.com", "a.example.com"}
	r.Spec.AllowSubdomains = true
	r.Spec.ServerFlag = true
	r.Spec.KeyType = "rsa"
	r.Spec.KeyBits = 2048
	r.Spec.KeyUsage = []string{"DigitalSignature", "KeyEncipherment"}

	t.Run("nil bao read → drift", func(t *testing.T) {
		require.False(t, r.IsEquivalentToDesiredState(map[string]any{"role": (*baoclient.PKIRoleSpec)(nil)}))
	})

	t.Run("matching state — order-insensitive on slices", func(t *testing.T) {
		current := &baoclient.PKIRoleSpec{
			AllowedDomains:  []string{"a.example.com", "b.example.com"},
			AllowSubdomains: true,
			ServerFlag:      true,
			KeyType:         "rsa",
			KeyBits:         2048,
			KeyUsage:        []string{"KeyEncipherment", "DigitalSignature"},
		}
		require.True(t, r.IsEquivalentToDesiredState(map[string]any{"role": current}))
	})

	t.Run("differing field → drift", func(t *testing.T) {
		current := &baoclient.PKIRoleSpec{
			AllowedDomains:  []string{"b.example.com", "a.example.com"},
			AllowSubdomains: false, // different
			ServerFlag:      true,
			KeyType:         "rsa",
			KeyBits:         2048,
			KeyUsage:        []string{"DigitalSignature", "KeyEncipherment"},
		}
		require.False(t, r.IsEquivalentToDesiredState(map[string]any{"role": current}))
	})

	t.Run("unset spec field treated as bao default — no drift", func(t *testing.T) {
		// CR omits keyBits; bao read says 2048. Comparator should NOT
		// see drift on a server default the spec didn't pin.
		minimal := &OpenBaoPKISecretEngineRole{}
		minimal.Spec.AllowAnyName = true
		current := &baoclient.PKIRoleSpec{
			AllowAnyName: true,
			KeyType:      "rsa",
			KeyBits:      2048,
		}
		require.True(t, minimal.IsEquivalentToDesiredState(map[string]any{"role": current}))
	})

	// Regression guard against the write-storm bug: a minimal spec
	// like {allowedDomains, allowSubdomains} must NOT observe drift
	// against bao's full read shape. Bao auto-fills server_flag,
	// client_flag, enforce_hostnames, allow_ip_sans, require_cn,
	// key_usage on every read — without applyDefaults handling all
	// of them, every reconcile would re-write the role.
	t.Run("minimal spec vs bao-defaulted read — no write storm", func(t *testing.T) {
		spec := &OpenBaoPKISecretEngineRole{}
		spec.Spec.AllowedDomains = []string{"example.com"}
		spec.Spec.AllowSubdomains = true
		// User did NOT set: serverFlag, clientFlag, enforceHostnames,
		// allowIpSans, requireCn, keyType, keyBits, keyUsage.

		// Bao's read shape after applying its server-side defaults:
		current := &baoclient.PKIRoleSpec{
			AllowedDomains:   []string{"example.com"},
			AllowSubdomains:  true,
			ServerFlag:       true,
			ClientFlag:       true,
			EnforceHostnames: true,
			AllowIPSANs:      true,
			RequireCN:        true,
			KeyType:          "rsa",
			KeyBits:          2048,
			KeyUsage:         []string{"DigitalSignature", "KeyEncipherment"},
		}
		require.True(t, spec.IsEquivalentToDesiredState(map[string]any{"role": current}),
			"a minimal spec must be equivalent to the bao read with defaults — otherwise "+
				"BaoWrite fires on every reconcile and the controller produces a write storm")
	})
}

func TestPKIRole_PrepareInternalValues_NoOp(t *testing.T) {
	t.Parallel()
	r := &OpenBaoPKISecretEngineRole{}
	require.NoError(t, r.PrepareInternalValues(context.Background(), r))
}

func TestPKIRole_RenameTracker_RoundTrip(t *testing.T) {
	t.Parallel()
	r := &OpenBaoPKISecretEngineRole{}
	r.SetLastWrittenBaoIdentity("web-server", "acme/")
	require.Equal(t, "web-server", r.LastWrittenBaoName())
	require.Equal(t, "acme/", r.LastWrittenOpenBaoNamespace())
}
