package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	baoclient "github.com/stakater-ab/openbao-config-operator/internal/client"
)

const (
	sampleAMPath = "oidc"
	sampleAMType = "oidc"
)

func TestOpenBaoAuthMethod_BaoName(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	m.Spec.Path = "/oidc/"
	require.Equal(t, "oidc", m.BaoName())
}

func TestOpenBaoAuthMethod_BaoPath_TrailingSlash(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	m.Spec.Path = "oidc"
	require.Equal(t, "oidc/", m.BaoPath())
}

func TestOpenBaoAuthMethod_GetPath_EmbedsType(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	m.Spec.Path = sampleAMPath
	m.Spec.Type = sampleAMType
	require.Contains(t, m.GetPath(), "sys/auth/oidc")
	require.Contains(t, m.GetPath(), "(oidc)")
}

func TestOpenBaoAuthMethod_IsValid_AcceptsBaseline(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	m.Spec.Path = sampleAMPath
	m.Spec.Type = sampleAMType
	ok, err := m.IsValid()
	require.True(t, ok)
	require.NoError(t, err)
}

func TestOpenBaoAuthMethod_IsValid_RejectsEmptyPath(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	m.Spec.Type = sampleAMType
	ok, err := m.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "spec.path")
}

func TestOpenBaoAuthMethod_IsValid_RejectsEmptyType(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	m.Spec.Path = sampleAMPath
	ok, err := m.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "spec.type")
}

func TestOpenBaoAuthMethod_IsValid_RejectsUnsupportedType(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	m.Spec.Path = sampleAMPath
	m.Spec.Type = "transit"
	ok, err := m.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "supported")
}

func TestOpenBaoAuthMethod_IsValid_AcceptsAllSupportedTypes(t *testing.T) {
	t.Parallel()
	for _, typ := range []string{"cert", "jwt", "oidc", "kubernetes", "approle", "userpass", "ldap"} {
		t.Run(typ, func(t *testing.T) {
			m := &OpenBaoAuthMethod{}
			m.Spec.Path = sampleAMPath
			m.Spec.Type = typ
			ok, err := m.IsValid()
			require.True(t, ok, "type=%s should be supported", typ)
			require.NoError(t, err)
		})
	}
}

// Drift comparator: matches when type, description, and config align.
func TestOpenBaoAuthMethod_IsEquivalent_AllAligned(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	m.Spec.Path = sampleAMPath
	m.Spec.Type = sampleAMType
	m.Spec.Description = "OIDC for tenants"
	m.Spec.Config.DefaultLeaseTTL = "1h"

	cur := &baoclient.AuthMethodMount{
		Type:        sampleAMType,
		Description: "OIDC for tenants",
		Config:      baoclient.AuthMethodConfig{DefaultLeaseTTL: "1h"},
	}
	require.True(t, m.IsEquivalent(map[string]any{"mount": cur}))
}

// IsEquivalent is a method alias for IsEquivalentToDesiredState.
func (d *OpenBaoAuthMethod) IsEquivalent(payload map[string]any) bool {
	return d.IsEquivalentToDesiredState(payload)
}

func TestOpenBaoAuthMethod_IsEquivalent_DifferentTypeIsDrift(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	m.Spec.Path = sampleAMPath
	m.Spec.Type = sampleAMType

	cur := &baoclient.AuthMethodMount{Type: "jwt"}
	require.False(t, m.IsEquivalent(map[string]any{"mount": cur}))
}

func TestOpenBaoAuthMethod_IsEquivalent_DescriptionWhitespaceTolerant(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	m.Spec.Path = sampleAMPath
	m.Spec.Type = sampleAMType
	m.Spec.Description = "  OIDC  "

	cur := &baoclient.AuthMethodMount{Type: sampleAMType, Description: "OIDC"}
	require.True(t, m.IsEquivalent(map[string]any{"mount": cur}))
}

// Empty desired field adopts bao's value (avoids write storm on a CR
// that doesn't override bao defaults).
func TestOpenBaoAuthMethod_IsEquivalent_EmptyConfigAdoptsBao(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	m.Spec.Path = sampleAMPath
	m.Spec.Type = sampleAMType

	cur := &baoclient.AuthMethodMount{
		Type: sampleAMType,
		Config: baoclient.AuthMethodConfig{
			DefaultLeaseTTL: "86400s",
			MaxLeaseTTL:     "604800s",
		},
	}
	require.True(t, m.IsEquivalent(map[string]any{"mount": cur}),
		"empty desired config must adopt bao defaults without drift")
}

func TestOpenBaoAuthMethod_IsEquivalent_ConfigDriftDetected(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	m.Spec.Path = sampleAMPath
	m.Spec.Type = sampleAMType
	m.Spec.Config.MaxLeaseTTL = "24h"

	cur := &baoclient.AuthMethodMount{
		Type:   sampleAMType,
		Config: baoclient.AuthMethodConfig{MaxLeaseTTL: "48h"},
	}
	require.False(t, m.IsEquivalent(map[string]any{"mount": cur}))
}

func TestOpenBaoAuthMethod_ToBaoSpec(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	m.Spec.Path = sampleAMPath
	m.Spec.Type = sampleAMType
	m.Spec.Description = "OIDC"
	m.Spec.Config.DefaultLeaseTTL = "1h"
	m.Spec.Config.ListingVisibility = "unauth"

	spec := m.ToBaoSpec()
	require.Equal(t, sampleAMType, spec.Type)
	require.Equal(t, "OIDC", spec.Description)
	require.Equal(t, "1h", spec.Config.DefaultLeaseTTL)
	require.Equal(t, "unauth", spec.Config.ListingVisibility)
}

func TestOpenBaoAuthMethod_StatusInterfaces_RoundTrip(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	require.False(t, m.IsBaoWritten())
	m.MarkBaoWritten()
	require.True(t, m.IsBaoWritten())
	m.SetLastWrittenBaoIdentity("oidc", "acme/")
	require.Equal(t, "oidc", m.LastWrittenBaoName())
	require.Equal(t, "acme/", m.LastWrittenOpenBaoNamespace())

	conds := []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"}}
	m.SetConditions(conds)
	require.Equal(t, conds, m.GetConditions())
}

func TestOpenBaoAuthMethod_PrepareInternalValues_NoOp(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	require.NoError(t, m.PrepareInternalValues(context.Background(), m))
	require.NoError(t, m.PrepareTLSConfig(context.Background(), m))
}

func TestOpenBaoAuthMethod_IsInitializedAndDeletable(t *testing.T) {
	t.Parallel()
	m := &OpenBaoAuthMethod{}
	require.True(t, m.IsInitialized())
	// Data-bearing kind: empty deletionPolicy means Retain. The full
	// policy table for every kind lives in deletionpolicy_test.go.
	require.False(t, m.IsDeletable())
}
