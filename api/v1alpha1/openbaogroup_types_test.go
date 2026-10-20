package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	baoclient "github.com/stakater/openbao-config-operator/internal/client"
)

const sampleGroupName = "team-a"

func TestOpenBaoGroup_BaoName_NormalizesAndPrefersSpec(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, metaName, specName, want string
	}{
		{"specName preferred", "meta", "spec-name", "spec-name"},
		{"metaName fallback", "meta-name", "", "meta-name"},
		{"trim+lower on metaName", "  Meta  ", "", "meta"},
		{"trim+lower on specName", "ignored", " Spec-Name ", "spec-name"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := &OpenBaoGroup{}
			g.Name = tc.metaName
			g.Spec.Name = tc.specName
			require.Equal(t, tc.want, g.BaoName())
		})
	}
}

func TestOpenBaoGroup_OpenBaoNamespace_TrimsWhitespace(t *testing.T) {
	t.Parallel()
	g := &OpenBaoGroup{}
	g.Spec.OpenBaoNamespace = "  acme/  "
	require.Equal(t, "acme/", g.OpenBaoNamespace())
}

func TestOpenBaoGroup_EffectiveType_DefaultsToInternal(t *testing.T) {
	t.Parallel()
	g := &OpenBaoGroup{}
	require.Equal(t, GroupTypeInternal, g.EffectiveType())
	g.Spec.Type = "External"
	require.Equal(t, GroupTypeExternal, g.EffectiveType())
}

func TestOpenBaoGroup_GetPath(t *testing.T) {
	t.Parallel()
	g := &OpenBaoGroup{}
	g.Name = sampleGroupName
	require.Equal(t, "identity/group/name/team-a", g.GetPath())
}

func TestOpenBaoGroup_IsValid_AcceptsCleanInternal(t *testing.T) {
	t.Parallel()
	g := &OpenBaoGroup{}
	g.Name = sampleGroupName
	g.Spec.Policies = []string{"reader"}
	ok, err := g.IsValid()
	require.True(t, ok)
	require.NoError(t, err)
}

func TestOpenBaoGroup_IsValid_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	g := &OpenBaoGroup{}
	ok, err := g.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "must not be empty")
}

func TestOpenBaoGroup_IsValid_RejectsExternalWithMembers(t *testing.T) {
	t.Parallel()
	g := &OpenBaoGroup{}
	g.Name = sampleGroupName
	g.Spec.Type = GroupTypeExternal
	g.Spec.MemberEntityIds = []string{"e-1"}
	ok, err := g.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "external")
}

func TestOpenBaoGroup_IsValid_RejectsInvalidType(t *testing.T) {
	t.Parallel()
	g := &OpenBaoGroup{}
	g.Name = sampleGroupName
	g.Spec.Type = "weird"
	ok, err := g.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "valid")
}

// Drift comparator must absorb bao's set semantics on slice fields and
// treat unset metadata as nil-equivalent. A naive DeepEqual on the
// raw bao read produces a write-storm.
func TestOpenBaoGroup_IsEquivalentToDesiredState_SortsAndNormalizes(t *testing.T) {
	t.Parallel()
	g := &OpenBaoGroup{}
	g.Name = sampleGroupName
	g.Spec.Policies = []string{"reader", "editor"}
	g.Spec.MemberEntityIds = []string{"e-2", "e-1"}

	// Out-of-order vs spec but same set — must be equivalent.
	cur := &baoclient.IdentityGroup{
		Type:            GroupTypeInternal,
		Policies:        []string{"editor", "reader"},
		MemberEntityIDs: []string{"e-1", "e-2"},
	}
	require.True(t, g.IsEquivalentToDesiredState(map[string]any{"group": cur}))

	// Different policy set must trigger drift.
	cur.Policies = []string{"reader"}
	require.False(t, g.IsEquivalentToDesiredState(map[string]any{"group": cur}))
}

// type=external groups bind members through aliases, not member ids;
// the comparator must skip member-id fields so a bao read echoing
// empty member arrays doesn't false-positive against a spec that
// (incorrectly) listed members and was already rejected by IsValid.
func TestOpenBaoGroup_IsEquivalentToDesiredState_ExternalSkipsMembers(t *testing.T) {
	t.Parallel()
	g := &OpenBaoGroup{}
	g.Name = sampleGroupName
	g.Spec.Type = GroupTypeExternal
	g.Spec.Policies = []string{"viewer"}

	cur := &baoclient.IdentityGroup{
		Type:     GroupTypeExternal,
		Policies: []string{"viewer"},
	}
	require.True(t, g.IsEquivalentToDesiredState(map[string]any{"group": cur}))
}

func TestOpenBaoGroup_IsEquivalentToDesiredState_DifferentTypeIsDrift(t *testing.T) {
	t.Parallel()
	g := &OpenBaoGroup{}
	g.Name = sampleGroupName
	cur := &baoclient.IdentityGroup{Type: GroupTypeExternal}
	require.False(t, g.IsEquivalentToDesiredState(map[string]any{"group": cur}),
		"spec=internal vs bao=external must be drift, not equivalence")
}

func TestOpenBaoGroup_ToBaoSpec_FillsTypeAndCarriesID(t *testing.T) {
	t.Parallel()
	g := &OpenBaoGroup{}
	g.Name = sampleGroupName
	g.Status.GroupID = "id-123"
	g.Spec.Policies = []string{"viewer"}
	spec := g.ToBaoSpec()
	require.Equal(t, "id-123", spec.ID)
	require.Equal(t, GroupTypeInternal, spec.Type)
	require.Equal(t, []string{"viewer"}, spec.Policies)
}

// Round-trip: status fields are read+written via the interface methods.
func TestOpenBaoGroup_StatusInterfaces_RoundTrip(t *testing.T) {
	t.Parallel()
	g := &OpenBaoGroup{}
	require.False(t, g.IsBaoWritten())
	g.MarkBaoWritten()
	require.True(t, g.IsBaoWritten())

	g.SetLastWrittenBaoIdentity("team-a", "acme/")
	require.Equal(t, "team-a", g.LastWrittenBaoName())
	require.Equal(t, "acme/", g.LastWrittenOpenBaoNamespace())

	conds := []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"}}
	g.SetConditions(conds)
	require.Equal(t, conds, g.GetConditions())
}

func TestOpenBaoGroup_PrepareInternalValues_NoOp(t *testing.T) {
	t.Parallel()
	g := &OpenBaoGroup{}
	require.NoError(t, g.PrepareInternalValues(context.Background(), g))
	require.NoError(t, g.PrepareTLSConfig(context.Background(), g))
}

func TestOpenBaoGroup_IsInitializedAndDeletable(t *testing.T) {
	t.Parallel()
	g := &OpenBaoGroup{}
	require.True(t, g.IsInitialized())
	require.True(t, g.IsDeletable())
}
