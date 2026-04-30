package v1alpha1

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// sampleNSName is a placeholder bao-namespace name used across the
// type-level tests; centralized to satisfy goconst on repeats.
const sampleNSName = "acme"

func TestOpenBaoNamespace_BaoName_NormalizesAndPrefersSpec(t *testing.T) {
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
			n := &OpenBaoNamespace{}
			n.Name = tc.metaName
			n.Spec.Name = tc.specName
			require.Equal(t, tc.want, n.BaoName())
		})
	}
}

func TestOpenBaoNamespace_OpenBaoNamespace_NormalizesWhitespace(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"", ""},
		{"acme/", "acme/"},
		{"  acme/  ", "acme/"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			n := &OpenBaoNamespace{}
			n.Spec.OpenBaoNamespace = tc.in
			require.Equal(t, tc.want, n.OpenBaoNamespace())
		})
	}
}

func TestOpenBaoNamespace_GetPath(t *testing.T) {
	t.Parallel()
	n := &OpenBaoNamespace{}
	n.Name = sampleNSName
	require.Equal(t, "sys/namespaces/acme", n.GetPath())
}

func TestOpenBaoNamespace_GetPayload(t *testing.T) {
	t.Parallel()
	n := &OpenBaoNamespace{}
	n.Name = sampleNSName
	got := n.GetPayload()
	require.Equal(t, "acme", got["name"])
}

// Bao namespaces have no per-namespace mutable spec; presence at the
// right path is the only state. IsEquivalentToDesiredState therefore
// returns true unconditionally — once BaoGet returns non-nil, no
// BaoWrite is needed. A "different" namespace name in the read shape
// is impossible because BaoGet queries by the spec's name — a
// mismatch surfaces as ErrNotFound, never as a populated-but-different
// payload.
func TestOpenBaoNamespace_IsEquivalentToDesiredState_AlwaysTrue(t *testing.T) {
	t.Parallel()
	n := &OpenBaoNamespace{}
	n.Name = sampleNSName
	require.True(t, n.IsEquivalentToDesiredState(map[string]any{"name": "acme"}))
	require.True(t, n.IsEquivalentToDesiredState(map[string]any{"name": "globex"}))
	require.True(t, n.IsEquivalentToDesiredState(map[string]any{}))
}

func TestOpenBaoNamespace_IsValid_AcceptsCleanName(t *testing.T) {
	t.Parallel()
	n := &OpenBaoNamespace{}
	n.Name = sampleNSName
	ok, err := n.IsValid()
	require.True(t, ok)
	require.NoError(t, err)
}

func TestOpenBaoNamespace_IsValid_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	n := &OpenBaoNamespace{}
	ok, err := n.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "must not be empty")
}

// Defense in depth: bao reserves a small set of names for its own
// internals. Reject at admission/IsValid so the user sees a stable
// error instead of a flapping bao 4xx.
func TestOpenBaoNamespace_IsValid_RejectsReservedNames(t *testing.T) {
	t.Parallel()
	for _, reserved := range []string{".", "..", "root", "sys", "audit", "auth", "cubbyhole", "identity"} {
		t.Run(reserved, func(t *testing.T) {
			n := &OpenBaoNamespace{}
			n.Name = reserved
			ok, err := n.IsValid()
			require.False(t, ok, "name %q must be rejected as reserved", reserved)
			require.ErrorContains(t, err, "reserved")
		})
	}
}

// spec.name is the LOCAL segment within the parent context; nesting
// is achieved via spec.openbaoNamespace. A slash in spec.name would
// bypass that model — IsValid rejects so the user is steered toward
// the explicit parent flag.
func TestOpenBaoNamespace_IsValid_RejectsSlashInName(t *testing.T) {
	t.Parallel()
	n := &OpenBaoNamespace{}
	n.Name = "acme/sub"
	ok, err := n.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "spec.openbaoNamespace")
}

func TestOpenBaoNamespace_IsInitialized_IsDeletable(t *testing.T) {
	t.Parallel()
	n := &OpenBaoNamespace{}
	require.True(t, n.IsInitialized())
	require.True(t, n.IsDeletable())
}

func TestOpenBaoNamespace_PrepareInternalValues_NoOp(t *testing.T) {
	t.Parallel()
	n := &OpenBaoNamespace{}
	require.NoError(t, n.PrepareInternalValues(context.Background(), n))
}

func TestOpenBaoNamespace_GetConditions_SetConditions_RoundTrip(t *testing.T) {
	t.Parallel()
	n := &OpenBaoNamespace{}
	require.Empty(t, n.GetConditions())
	conds := []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"}}
	n.SetConditions(conds)
	require.Equal(t, conds, n.GetConditions())
}

func TestOpenBaoNamespace_BaoWritten_RoundTrip(t *testing.T) {
	t.Parallel()
	n := &OpenBaoNamespace{}
	require.False(t, n.IsBaoWritten())
	n.MarkBaoWritten()
	require.True(t, n.IsBaoWritten())
}

// Reserved-names list stability: if the upstream OpenBao docs grow the
// list, we want this test to flag the gap. Pinned to the docs at
// creation time; bump alongside any real list change.
func TestOpenBaoNamespace_ReservedNamesAreBaoOfficial(t *testing.T) {
	t.Parallel()
	want := []string{".", "..", "root", "sys", "audit", "auth", "cubbyhole", "identity"}
	require.Equal(t, len(want), len(reservedBaoNamespaceNames),
		"reservedBaoNamespaceNames diverged from documented OpenBao reserved list")
	for _, name := range want {
		_, ok := reservedBaoNamespaceNames[name]
		require.True(t, ok, "%q must be in the reserved-names map", name)
	}
}

// Placeholder check: the "/" rejection message points at the right
// spec field so the user knows where to fix the manifest.
func TestOpenBaoNamespace_IsValid_SlashRejectionPointsAtParentField(t *testing.T) {
	t.Parallel()
	n := &OpenBaoNamespace{}
	n.Name = "a/b/c"
	_, err := n.IsValid()
	require.NotNil(t, err)
	require.True(t, strings.Contains(err.Error(), "spec.openbaoNamespace"),
		"error must direct the user to spec.openbaoNamespace; got: %v", err)
}
