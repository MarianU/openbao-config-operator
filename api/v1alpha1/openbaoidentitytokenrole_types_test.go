package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	baoclient "github.com/stakater-ab/openbao-config-operator/internal/client"
)

const (
	sampleITRName = "aws-tokens"
	sampleITRKey  = "platform"
)

func TestOpenBaoIdentityTokenRole_BaoName_PrefersSpec(t *testing.T) {
	t.Parallel()
	r := &OpenBaoIdentityTokenRole{}
	r.Name = "kube-name"
	r.Spec.Name = sampleITRName
	require.Equal(t, sampleITRName, r.BaoName())

	r.Spec.Name = ""
	require.Equal(t, "kube-name", r.BaoName())
}

func TestOpenBaoIdentityTokenRole_BaoName_NormalizesWhitespaceAndCase(t *testing.T) {
	t.Parallel()
	r := &OpenBaoIdentityTokenRole{}
	r.Spec.Name = "  AWS-Tokens  "
	require.Equal(t, "aws-tokens", r.BaoName())
}

func TestOpenBaoIdentityTokenRole_GetPath(t *testing.T) {
	t.Parallel()
	r := &OpenBaoIdentityTokenRole{}
	r.Name = sampleITRName
	require.Equal(t, "identity/oidc/role/aws-tokens", r.GetPath())
}

func TestOpenBaoIdentityTokenRole_IsValid_AcceptsBaseline(t *testing.T) {
	t.Parallel()
	r := &OpenBaoIdentityTokenRole{}
	r.Name = sampleITRName
	r.Spec.Key = sampleITRKey
	ok, err := r.IsValid()
	require.True(t, ok)
	require.NoError(t, err)
}

func TestOpenBaoIdentityTokenRole_IsValid_RejectsEmptyKey(t *testing.T) {
	t.Parallel()
	r := &OpenBaoIdentityTokenRole{}
	r.Name = sampleITRName
	ok, err := r.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "spec.key")
}

func TestOpenBaoIdentityTokenRole_IsValid_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	r := &OpenBaoIdentityTokenRole{}
	r.Spec.Key = sampleITRKey
	ok, err := r.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "must not be empty")
}

// Drift comparator: TTL normalises bao's int-second response to <n>s
// for stable round-trip with the spec's bao-duration string.
func TestOpenBaoIdentityTokenRole_IsEquivalent_TTLRoundTrip(t *testing.T) {
	t.Parallel()
	r := &OpenBaoIdentityTokenRole{}
	r.Name = sampleITRName
	r.Spec.Key = sampleITRKey
	r.Spec.TTL = "3600s"

	cur := &baoclient.IdentityTokenRoleSpec{
		Key: sampleITRKey,
		TTL: "3600s", // already-normalized form from the wrapper
	}
	require.True(t, r.IsEquivalent(map[string]any{"role": cur}))

	cur.TTL = "1800s"
	require.False(t, r.IsEquivalent(map[string]any{"role": cur}),
		"different TTL must trigger drift")
}

// IsEquivalent is a method alias for IsEquivalentToDesiredState
// declared in the type file. Using the longer name in tests is
// noisy, so this helper delegates.
func (r *OpenBaoIdentityTokenRole) IsEquivalent(payload map[string]any) bool {
	return r.IsEquivalentToDesiredState(payload)
}

// Spec leaving TTL empty must not false-positive against a bao read
// echoing the key's default TTL (no drift).
func TestOpenBaoIdentityTokenRole_IsEquivalent_EmptyTTLAdoptsBao(t *testing.T) {
	t.Parallel()
	r := &OpenBaoIdentityTokenRole{}
	r.Name = sampleITRName
	r.Spec.Key = sampleITRKey

	cur := &baoclient.IdentityTokenRoleSpec{Key: sampleITRKey, TTL: "86400s"}
	require.True(t, r.IsEquivalent(map[string]any{"role": cur}))
}

func TestOpenBaoIdentityTokenRole_IsEquivalent_DifferentKey(t *testing.T) {
	t.Parallel()
	r := &OpenBaoIdentityTokenRole{}
	r.Name = sampleITRName
	r.Spec.Key = sampleITRKey

	cur := &baoclient.IdentityTokenRoleSpec{Key: "other", TTL: "3600s"}
	require.False(t, r.IsEquivalent(map[string]any{"role": cur}))
}

func TestOpenBaoIdentityTokenRole_ToBaoSpec_TrimsKey(t *testing.T) {
	t.Parallel()
	r := &OpenBaoIdentityTokenRole{}
	r.Name = sampleITRName
	r.Spec.Key = "  platform  "
	r.Spec.Template = "{}"
	r.Spec.ClientID = "arn:..."
	r.Spec.TTL = "  1h  "
	spec := r.ToBaoSpec()
	require.Equal(t, sampleITRKey, spec.Key)
	require.Equal(t, "{}", spec.Template)
	require.Equal(t, "arn:...", spec.ClientID)
	require.Equal(t, "1h", spec.TTL)
}

func TestOpenBaoIdentityTokenRole_StatusInterfaces_RoundTrip(t *testing.T) {
	t.Parallel()
	r := &OpenBaoIdentityTokenRole{}
	require.False(t, r.IsBaoWritten())
	r.MarkBaoWritten()
	require.True(t, r.IsBaoWritten())
	r.SetLastWrittenBaoIdentity("aws-tokens", "acme/")
	require.Equal(t, "aws-tokens", r.LastWrittenBaoName())
	require.Equal(t, "acme/", r.LastWrittenOpenBaoNamespace())

	conds := []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"}}
	r.SetConditions(conds)
	require.Equal(t, conds, r.GetConditions())
}

func TestOpenBaoIdentityTokenRole_PrepareInternalValues_NoOp(t *testing.T) {
	t.Parallel()
	r := &OpenBaoIdentityTokenRole{}
	require.NoError(t, r.PrepareInternalValues(context.Background(), r))
	require.NoError(t, r.PrepareTLSConfig(context.Background(), r))
}

func TestOpenBaoIdentityTokenRole_IsInitializedAndDeletable(t *testing.T) {
	t.Parallel()
	r := &OpenBaoIdentityTokenRole{}
	require.True(t, r.IsInitialized())
	require.True(t, r.IsDeletable())
}
