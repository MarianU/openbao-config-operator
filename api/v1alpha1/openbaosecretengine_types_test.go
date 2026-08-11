package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// secretMountPath is the canonical valid bao path used across these
// type-level tests. Centralized to satisfy goconst across repeats.
const secretMountPath = "secret"

func TestOpenBaoSecretEngine_OpenBaoNamespace_NormalizesWhitespace(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"", ""},
		{"acme/", "acme/"},
		{"  acme/  ", "acme/"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			m := &OpenBaoSecretEngine{}
			m.Spec.OpenBaoNamespace = tc.in
			require.Equal(t, tc.want, m.OpenBaoNamespace())
		})
	}
}

func TestOpenBaoSecretEngine_BaoPath_AddsTrailingSlash(t *testing.T) {
	t.Parallel()
	m := &OpenBaoSecretEngine{}
	m.Spec.Path = secretMountPath
	require.Equal(t, "secret/", m.BaoPath())

	m.Spec.Path = "secret/"
	require.Equal(t, "secret/", m.BaoPath())

	m.Spec.Path = "/secret/"
	require.Equal(t, "secret/", m.BaoPath())
}

func TestOpenBaoSecretEngine_EngineType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		mutate   func(m *OpenBaoSecretEngine)
		wantType string
		wantOK   bool
	}{
		{"kvV2 → kv", func(m *OpenBaoSecretEngine) { m.Spec.KvV2 = &KvV2Spec{} }, "kv", true},
		{"transit → transit", func(m *OpenBaoSecretEngine) { m.Spec.Transit = &TransitSpec{} }, "transit", true},
		{"pki → pki", func(m *OpenBaoSecretEngine) { m.Spec.PKI = &PKISpec{} }, "pki", true},
		{"none → not ok", func(m *OpenBaoSecretEngine) {}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &OpenBaoSecretEngine{}
			tc.mutate(m)
			baoType, ok := m.EngineType()
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantType, baoType)
		})
	}
}

func TestOpenBaoSecretEngine_GetPath_EmbedsEngineType(t *testing.T) {
	t.Parallel()
	mKV := &OpenBaoSecretEngine{}
	mKV.Spec.Path = secretMountPath
	mKV.Spec.KvV2 = &KvV2Spec{}
	require.Contains(t, mKV.GetPath(), "sys/mounts/secret")
	require.Contains(t, mKV.GetPath(), "(kv)")

	mPKI := &OpenBaoSecretEngine{}
	mPKI.Spec.Path = "pki"
	mPKI.Spec.PKI = &PKISpec{}
	require.Contains(t, mPKI.GetPath(), "sys/mounts/pki")
	require.Contains(t, mPKI.GetPath(), "(pki)")
}

func TestOpenBaoSecretEngine_GetPayload_KvV2EmitsVersion2(t *testing.T) {
	t.Parallel()
	m := &OpenBaoSecretEngine{}
	m.Spec.Path = secretMountPath
	m.Spec.Description = "kv-v2 mount"
	m.Spec.KvV2 = &KvV2Spec{}

	got := m.GetPayload()
	require.Equal(t, "kv-v2 mount", got["description"])
	opts, ok := got["options"].(map[string]string)
	require.True(t, ok, "kv-v2 GetPayload must emit options as map[string]string")
	require.Equal(t, "2", opts["version"])
}

func TestOpenBaoSecretEngine_IsEquivalentToDesiredState(t *testing.T) {
	t.Parallel()
	m := &OpenBaoSecretEngine{}
	m.Spec.KvV2 = &KvV2Spec{}
	m.Spec.Description = "tenant kv-v2"

	t.Run("identical bao read", func(t *testing.T) {
		current := map[string]any{
			"description": "tenant kv-v2",
			"options":     map[string]string{"version": "2"},
		}
		require.True(t, m.IsEquivalentToDesiredState(current))
	})

	t.Run("description differs", func(t *testing.T) {
		current := map[string]any{
			"description": "different",
			"options":     map[string]string{"version": "2"},
		}
		require.False(t, m.IsEquivalentToDesiredState(current))
	})

	t.Run("missing version triggers drift", func(t *testing.T) {
		current := map[string]any{
			"description": "tenant kv-v2",
			"options":     map[string]string{},
		}
		require.False(t, m.IsEquivalentToDesiredState(current))
	})

	t.Run("options as map[string]interface{} (vault SDK shape) still matches", func(t *testing.T) {
		current := map[string]any{
			"description": "tenant kv-v2",
			"options":     map[string]interface{}{"version": "2"},
		}
		require.True(t, m.IsEquivalentToDesiredState(current),
			"comparator must coerce both options shapes")
	})

	t.Run("description whitespace tolerant", func(t *testing.T) {
		current := map[string]any{
			"description": "  tenant kv-v2  ",
			"options":     map[string]string{"version": "2"},
		}
		require.True(t, m.IsEquivalentToDesiredState(current))
	})
}

// PKI and Transit have no options analogue today; the comparator must
// treat a nil/empty options map on the read side as equivalent to the
// no-options desired payload.
func TestOpenBaoSecretEngine_IsEquivalentToDesiredState_NoOptionsEngines(t *testing.T) {
	t.Parallel()
	m := &OpenBaoSecretEngine{}
	m.Spec.PKI = &PKISpec{}

	current := map[string]any{
		"description": "",
		"options":     map[string]string{},
	}
	require.True(t, m.IsEquivalentToDesiredState(current),
		"PKI mount with no description must match no-options bao read")

	currentNil := map[string]any{
		"description": "",
		"options":     nil,
	}
	require.True(t, m.IsEquivalentToDesiredState(currentNil),
		"nil options on read must be treated as empty map")
}

func TestOpenBaoSecretEngine_IsValid(t *testing.T) {
	t.Parallel()
	t.Run("no slot rejected", func(t *testing.T) {
		m := &OpenBaoSecretEngine{}
		m.Spec.Path = secretMountPath
		ok, err := m.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "exactly one")
	})

	t.Run("two slots rejected", func(t *testing.T) {
		m := &OpenBaoSecretEngine{}
		m.Spec.Path = secretMountPath
		m.Spec.KvV2 = &KvV2Spec{}
		m.Spec.Transit = &TransitSpec{}
		ok, err := m.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "only one")
	})

	t.Run("empty path rejected", func(t *testing.T) {
		m := &OpenBaoSecretEngine{}
		m.Spec.KvV2 = &KvV2Spec{}
		ok, err := m.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "spec.path")
	})

	t.Run("kvV2 only accepted", func(t *testing.T) {
		m := &OpenBaoSecretEngine{}
		m.Spec.Path = secretMountPath
		m.Spec.KvV2 = &KvV2Spec{}
		ok, err := m.IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})

	t.Run("pki only accepted", func(t *testing.T) {
		m := &OpenBaoSecretEngine{}
		m.Spec.Path = "pki"
		m.Spec.PKI = &PKISpec{}
		ok, err := m.IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})
}

func TestOpenBaoSecretEngine_IsInitialized_IsDeletable(t *testing.T) {
	t.Parallel()
	m := &OpenBaoSecretEngine{}
	require.True(t, m.IsInitialized())
	// Data-bearing kind: empty deletionPolicy means Retain. The full
	// policy table for every kind lives in deletionpolicy_test.go.
	require.False(t, m.IsDeletable())
}

func TestOpenBaoSecretEngine_PrepareInternalValues_NoOp(t *testing.T) {
	t.Parallel()
	m := &OpenBaoSecretEngine{}
	require.NoError(t, m.PrepareInternalValues(context.Background(), m))
}

func TestOpenBaoSecretEngine_GetConditions_SetConditions_RoundTrip(t *testing.T) {
	t.Parallel()
	m := &OpenBaoSecretEngine{}
	require.Empty(t, m.GetConditions())
	conds := []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"}}
	m.SetConditions(conds)
	require.Equal(t, conds, m.GetConditions())
}

func TestOpenBaoSecretEngine_BaoWritten_RoundTrip(t *testing.T) {
	t.Parallel()
	m := &OpenBaoSecretEngine{}
	require.False(t, m.IsBaoWritten())
	m.MarkBaoWritten()
	require.True(t, m.IsBaoWritten())
}

func TestOpenBaoSecretEngine_LastWritten_RoundTrip(t *testing.T) {
	t.Parallel()
	m := &OpenBaoSecretEngine{}
	require.Empty(t, m.LastWrittenBaoName())
	require.Empty(t, m.LastWrittenOpenBaoNamespace())
	m.SetLastWrittenBaoIdentity("secret", "acme/")
	require.Equal(t, "secret", m.LastWrittenBaoName())
	require.Equal(t, "acme/", m.LastWrittenOpenBaoNamespace())
}
