package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	baoclient "github.com/stakater-ab/openbao-config-operator/internal/client"
)

const (
	sampleAliasName  = "alice@example.com"
	sampleAliasMount = "auth_oidc_abc123"
	sampleAliasNS    = "default"
	sampleAliasGID   = "g-1"
)

func TestOpenBaoGroupAlias_BaoName_PrefersSpec(t *testing.T) {
	t.Parallel()
	a := &OpenBaoGroupAlias{}
	a.Name = "kube-name"
	a.Spec.Name = sampleAliasName
	require.Equal(t, sampleAliasName, a.BaoName())

	a.Spec.Name = ""
	require.Equal(t, "kube-name", a.BaoName())
}

func TestOpenBaoGroupAlias_MountAccessor_TrimsWhitespace(t *testing.T) {
	t.Parallel()
	a := &OpenBaoGroupAlias{}
	a.Spec.MountAccessor = "  " + sampleAliasMount + "  "
	require.Equal(t, sampleAliasMount, a.MountAccessor())
}

func TestOpenBaoGroupAlias_GetPath_DependsOnAliasID(t *testing.T) {
	t.Parallel()
	a := &OpenBaoGroupAlias{}
	a.Name = sampleAliasName
	a.Spec.MountAccessor = sampleAliasMount
	require.Contains(t, a.GetPath(), "mount=", "no AliasID → diagnostic form")

	a.Status.AliasID = "ga-99"
	require.Equal(t, "identity/group-alias/id/ga-99", a.GetPath())
}

func TestOpenBaoGroupAlias_IsValid_AcceptsCanonicalID(t *testing.T) {
	t.Parallel()
	a := &OpenBaoGroupAlias{}
	a.Name = sampleAliasName
	a.Spec.MountAccessor = sampleAliasMount
	a.Spec.CanonicalID = "g-100"
	ok, err := a.IsValid()
	require.True(t, ok)
	require.NoError(t, err)
}

func TestOpenBaoGroupAlias_IsValid_AcceptsGroupRef(t *testing.T) {
	t.Parallel()
	a := &OpenBaoGroupAlias{}
	a.Name = sampleAliasName
	a.Spec.MountAccessor = sampleAliasMount
	a.Spec.CanonicalGroupRef = &OpenBaoGroupRef{Name: sampleGroupName}
	ok, err := a.IsValid()
	require.True(t, ok)
	require.NoError(t, err)
}

func TestOpenBaoGroupAlias_IsValid_RejectsNeither(t *testing.T) {
	t.Parallel()
	a := &OpenBaoGroupAlias{}
	a.Name = sampleAliasName
	a.Spec.MountAccessor = sampleAliasMount
	ok, err := a.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "exactly one")
}

func TestOpenBaoGroupAlias_IsValid_RejectsBoth(t *testing.T) {
	t.Parallel()
	a := &OpenBaoGroupAlias{}
	a.Name = sampleAliasName
	a.Spec.MountAccessor = sampleAliasMount
	a.Spec.CanonicalID = sampleAliasGID
	a.Spec.CanonicalGroupRef = &OpenBaoGroupRef{Name: sampleGroupName}
	ok, err := a.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "only one")
}

func TestOpenBaoGroupAlias_IsValid_RejectsEmptyMountAccessor(t *testing.T) {
	t.Parallel()
	a := &OpenBaoGroupAlias{}
	a.Name = sampleAliasName
	a.Spec.CanonicalID = sampleAliasGID
	ok, err := a.IsValid()
	require.False(t, ok)
	require.ErrorContains(t, err, "mountAccessor")
}

// PrepareInternalValues with spec.canonicalId stamps it directly.
func TestOpenBaoGroupAlias_PrepareInternalValues_LiteralCanonicalID(t *testing.T) {
	t.Parallel()
	a := &OpenBaoGroupAlias{}
	a.Spec.CanonicalID = "g-99"
	require.NoError(t, a.PrepareInternalValues(context.Background(), a))
	require.Equal(t, "g-99", a.Status.ResolvedCanonicalID)
}

// PrepareInternalValues with spec.canonicalGroupRef pulls from the
// referenced OpenBaoGroup's status.GroupID.
func TestOpenBaoGroupAlias_PrepareInternalValues_GroupRef_Resolves(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, AddToScheme(scheme))

	parent := &OpenBaoGroup{}
	parent.Name = sampleGroupName
	parent.Namespace = sampleAliasNS
	parent.Status.GroupID = "g-resolved"

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(parent).
		WithStatusSubresource(parent).
		Build()

	a := &OpenBaoGroupAlias{}
	a.Namespace = sampleAliasNS
	a.Spec.CanonicalGroupRef = &OpenBaoGroupRef{Name: sampleGroupName}

	//nolint:staticcheck // matches the shared base contract
	ctx := context.WithValue(context.Background(), "kubeClient", cl)
	require.NoError(t, a.PrepareInternalValues(ctx, a))
	require.Equal(t, "g-resolved", a.Status.ResolvedCanonicalID)
}

// Parent group exists but hasn't been written to bao yet (status.GroupID
// empty). Surface as error so the controller requeues — the alias must
// not be created with an empty canonical_id.
func TestOpenBaoGroupAlias_PrepareInternalValues_GroupRef_ParentNotReady(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, AddToScheme(scheme))

	parent := &OpenBaoGroup{}
	parent.Name = sampleGroupName
	parent.Namespace = sampleAliasNS
	// status.GroupID empty

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(parent).
		WithStatusSubresource(parent).
		Build()

	a := &OpenBaoGroupAlias{}
	a.Namespace = sampleAliasNS
	a.Spec.CanonicalGroupRef = &OpenBaoGroupRef{Name: sampleGroupName}

	//nolint:staticcheck // matches the shared base contract
	ctx := context.WithValue(context.Background(), "kubeClient", cl)
	err := a.PrepareInternalValues(ctx, a)
	require.Error(t, err)
	require.Contains(t, err.Error(), "groupId is empty")
}

// PrepareInternalValues with a missing referenced group surfaces the
// 404 from the apiserver — the controller will classify as
// ReasonInternalError and requeue.
func TestOpenBaoGroupAlias_PrepareInternalValues_GroupRef_Missing(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, AddToScheme(scheme))

	cl := crfake.NewClientBuilder().WithScheme(scheme).Build()

	a := &OpenBaoGroupAlias{}
	a.Namespace = sampleAliasNS
	a.Spec.CanonicalGroupRef = &OpenBaoGroupRef{Name: "ghost"}

	//nolint:staticcheck // matches the shared base contract
	ctx := context.WithValue(context.Background(), "kubeClient", cl)
	require.Error(t, a.PrepareInternalValues(ctx, a))
}

// Drift comparator: name, mount, canonical id all factor in.
func TestOpenBaoGroupAlias_IsEquivalentToDesiredState(t *testing.T) {
	t.Parallel()
	a := &OpenBaoGroupAlias{}
	a.Name = sampleAliasName
	a.Spec.MountAccessor = sampleAliasMount
	a.Status.ResolvedCanonicalID = sampleAliasGID

	cur := &baoclient.IdentityGroupAlias{
		Name:          sampleAliasName,
		MountAccessor: sampleAliasMount,
		CanonicalID:   sampleAliasGID,
	}
	require.True(t, a.IsEquivalentToDesiredState(map[string]any{"alias": cur}))

	// canonical id flip → drift.
	cur.CanonicalID = "g-2"
	require.False(t, a.IsEquivalentToDesiredState(map[string]any{"alias": cur}))

	// name flip → drift.
	cur.CanonicalID = sampleAliasGID
	cur.Name = "other"
	require.False(t, a.IsEquivalentToDesiredState(map[string]any{"alias": cur}))
}

// Use a non-default scheme builder type assertion to avoid pulling
// in unused imports.
var _ client.Object = &OpenBaoGroupAlias{}
var _ metav1.Object = &OpenBaoGroupAlias{}

func TestOpenBaoGroupAlias_StatusInterfaces_RoundTrip(t *testing.T) {
	t.Parallel()
	a := &OpenBaoGroupAlias{}
	require.False(t, a.IsBaoWritten())
	a.MarkBaoWritten()
	require.True(t, a.IsBaoWritten())
	a.SetLastWrittenBaoIdentity("alias-name", "acme/")
	require.Equal(t, "alias-name", a.LastWrittenBaoName())
	require.Equal(t, "acme/", a.LastWrittenOpenBaoNamespace())
}

func TestOpenBaoGroupAlias_ToBaoSpec_CarriesStatusFields(t *testing.T) {
	t.Parallel()
	a := &OpenBaoGroupAlias{}
	a.Name = sampleAliasName
	a.Spec.MountAccessor = sampleAliasMount
	a.Status.AliasID = "ga-77"
	a.Status.ResolvedCanonicalID = "g-99"
	spec := a.ToBaoSpec()
	require.Equal(t, "ga-77", spec.ID)
	require.Equal(t, sampleAliasName, spec.Name)
	require.Equal(t, sampleAliasMount, spec.MountAccessor)
	require.Equal(t, "g-99", spec.CanonicalID)
}
