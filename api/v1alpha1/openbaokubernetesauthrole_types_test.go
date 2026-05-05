package v1alpha1

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// validKAERName is a placeholder metadata.name that satisfies BaoName()
// + the IsValid name regex; tests that focus on other branches reuse
// it so they don't trip the name guard.
const validKAERName = "valid-name"

// kubernetesMount is the auth mount path used across the type-level
// tests. Bare repeats trip goconst; centralize here.
const kubernetesMount = "kubernetes"

// KAERNamePattern mirrors the +kubebuilder:validation:Pattern marker on
// OpenBaoKubernetesAuthRoleSpec.Name. End-to-end enforcement is verified
// in the controller's crd_validation_test.go via envtest; this unit-level
// regex test documents the anchoring intent and catches off-by-one
// mistakes during local iteration. Keep both in sync when changing the
// pattern.
const KAERNamePattern = `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`

// Regression: OpenAPI v3 `pattern` does substring match by default, so
// an unanchored regex like `[a-z0-9]([-a-z0-9]*[a-z0-9])?` accepts
// "Bad_Name1" because the substring "a" matches. Anchoring with ^…$
// is required.
func TestKAER_NamePattern_AnchoredAndStrict(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(KAERNamePattern)

	cases := []struct {
		in     string
		accept bool
	}{
		{"editor", true},
		{"team-a-editor", true},
		{"123abc", true},
		{"a", true},
		{"a-b", true},
		{"Bad_Name1", false},
		{"-leading", false},
		{"trailing-", false},
		{"UPPER", false},
		{"with_underscore", false},
		{"with.dot", false},
		{"", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got := re.MatchString(tc.in)
			require.Equal(t, tc.accept, got, "input %q: want accept=%v got %v", tc.in, tc.accept, got)
		})
	}
}

func TestKAER_BaoName_NormalizesAndPrefersSpec(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		metaName string
		specName string
		want     string
	}{
		{"specName preferred over metaName", "meta-name", "spec-name", "spec-name"},
		{"metaName fallback when specName empty", "meta-name", "", "meta-name"},
		{"trim whitespace on metaName fallback", "  meta  ", "", "meta"},
		{"lowercase normalization on metaName", "Meta-Name", "", "meta-name"},
		{"trim and lowercase on specName", "ignored-meta", " Spec-Name ", "spec-name"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &OpenBaoKubernetesAuthRole{}
			r.Name = tc.metaName
			r.Spec.Name = tc.specName
			require.Equal(t, tc.want, r.BaoName())
		})
	}
}

func TestKAER_OpenBaoNamespace_NormalizesWhitespace(t *testing.T) {
	t.Parallel()
	tests := []struct {
		spec, want string
	}{
		{"", ""},
		{"acme/", "acme/"},
		{"  acme/  ", "acme/"},
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			r := &OpenBaoKubernetesAuthRole{}
			r.Spec.OpenBaoNamespace = tc.spec
			require.Equal(t, tc.want, r.OpenBaoNamespace())
		})
	}
}

func TestKAER_GetPath_ShapeIsAuthMountRoleName(t *testing.T) {
	t.Parallel()
	r := &OpenBaoKubernetesAuthRole{}
	r.Name = "team-a"
	r.Spec.Path = kubernetesMount
	require.Equal(t, "auth/kubernetes/role/team-a", r.GetPath())

	// trailing slashes are cleansed, not duplicated
	r.Spec.Path = "kubernetes/"
	require.Equal(t, "auth/kubernetes/role/team-a", r.GetPath())
}

// X-Vault-Namespace scopes the call; the path stays relative. GetPath
// must not embed spec.openbaoNamespace into the URL.
func TestKAER_GetPath_DoesNotIncludeOpenBaoNamespace(t *testing.T) {
	t.Parallel()
	r := &OpenBaoKubernetesAuthRole{}
	r.Name = "team-a"
	r.Spec.Path = kubernetesMount
	r.Spec.OpenBaoNamespace = "acme/"
	require.Equal(t, "auth/kubernetes/role/team-a", r.GetPath(),
		"OpenBao namespace must travel as a header, not in the bao path")
}

func TestKAER_IsValid_RejectsXORViolation(t *testing.T) {
	t.Parallel()

	withSelector := func() *OpenBaoKubernetesAuthRole {
		r := &OpenBaoKubernetesAuthRole{}
		r.Name = validKAERName
		r.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"k": "v"}}
		return r
	}
	withList := func(ns ...string) *OpenBaoKubernetesAuthRole {
		r := &OpenBaoKubernetesAuthRole{}
		r.Name = validKAERName
		r.Spec.TargetNamespaces.TargetNamespaces = ns
		return r
	}

	t.Run("both set rejected", func(t *testing.T) {
		t.Parallel()
		r := withSelector()
		r.Spec.TargetNamespaces.TargetNamespaces = []string{"a"}
		ok, err := r.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "only one of")
	})

	t.Run("neither set rejected", func(t *testing.T) {
		t.Parallel()
		r := &OpenBaoKubernetesAuthRole{}
		r.Name = validKAERName
		ok, err := r.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "must be specified")
	})

	t.Run("empty list rejected (present-but-empty collides with not-found)", func(t *testing.T) {
		t.Parallel()
		// Defense in depth: kubebuilder MinItems=1 catches this at admission,
		// but a stale CRD or fake client can bypass it. Without this guard
		// BaoGet treats the empty read as "not found" and the controller
		// loops on create.
		r := withList()
		r.Spec.TargetNamespaces.TargetNamespaces = []string{}
		ok, err := r.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "must not be empty")
	})

	t.Run("selector-only accepted", func(t *testing.T) {
		t.Parallel()
		ok, err := withSelector().IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})

	t.Run("list-only accepted", func(t *testing.T) {
		t.Parallel()
		ok, err := withList("ns-a", "ns-b").IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})
}

// IsValid runs after BaoName() normalization (TrimSpace + ToLower) and
// must reject any name that doesn't match the anchored DNS-1123 shape.
// The +kubebuilder:validation:Pattern marker on spec.name applies
// pre-normalization, so a CR whose admission was bypassed (stale CRD,
// fake client, schema-relaxed apply) and whose metadata.name is e.g.
// "FOO BAR" would normalize to "foo bar" — still invalid for bao.
// Without this guard the role write fails at bao with a 400 mid-
// reconcile instead of being rejected up front as a spec problem.
func TestKAER_IsValid_RejectsNameThatNormalizationCantClean(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		metaName string
		specName string
		wantOK   bool
	}{
		{"metaName with space stays invalid post-normalize", "FOO BAR", "", false},
		{"specName with space stays invalid post-normalize", "ignored", "Spec Name", false},
		{"metaName with underscore stays invalid post-normalize", "foo_bar", "", false},
		{"clean name accepted", "team-a-readers", "", true},
		{"messy specName cleaned by trim+lower passes", "ignored", "  Team-A  ", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &OpenBaoKubernetesAuthRole{}
			r.Name = tc.metaName
			r.Spec.Name = tc.specName
			r.Spec.TargetNamespaces.TargetNamespaces = []string{"ns-a"}
			ok, err := r.IsValid()
			if tc.wantOK {
				require.True(t, ok)
				require.NoError(t, err)
			} else {
				require.False(t, ok, "metaName=%q specName=%q should have been rejected", tc.metaName, tc.specName)
				require.Error(t, err)
				require.Contains(t, err.Error(), "bao name")
			}
		})
	}
}

// Bao does not guarantee a stable order on bound_service_account_namespaces
// reads. A naive reflect.DeepEqual on the raw payloads would see drift on
// every reconcile after the first reorder and re-upsert in a 5-minute loop.
func TestKAER_IsEquivalentToDesiredState_OrderInsensitiveBoundNamespaces(t *testing.T) {
	t.Parallel()
	r := &OpenBaoKubernetesAuthRole{}
	r.Spec.Path = kubernetesMount
	r.Spec.Policies = []string{"editor"}
	r.Spec.TargetServiceAccounts = []string{"default"}
	r.SetInternalNamespaces([]string{"a", "b", "c"})

	current := map[string]any{
		"bound_service_account_names":      []string{"default"},
		"bound_service_account_namespaces": []string{"c", "a", "b"},
		"token_policies":                   []string{"editor"},
	}
	require.True(t, r.IsEquivalentToDesiredState(current),
		"bound_service_account_namespaces must be compared order-insensitive")

	currentExtra := map[string]any{
		"bound_service_account_names":      []string{"default"},
		"bound_service_account_namespaces": []string{"a", "b", "c", "d"},
		"token_policies":                   []string{"editor"},
	}
	require.False(t, r.IsEquivalentToDesiredState(currentExtra))

	currentDiffPolicies := map[string]any{
		"bound_service_account_names":      []string{"default"},
		"bound_service_account_namespaces": []string{"a", "b", "c"},
		"token_policies":                   []string{"viewer"},
	}
	require.False(t, r.IsEquivalentToDesiredState(currentDiffPolicies))
}

func TestKAER_GetConditions_SetConditions_RoundTrip(t *testing.T) {
	t.Parallel()
	r := &OpenBaoKubernetesAuthRole{}
	require.Empty(t, r.GetConditions())

	conds := []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"}}
	r.SetConditions(conds)
	require.Equal(t, conds, r.GetConditions())
}

func TestKAER_IsBaoWritten_MarkBaoWritten_RoundTrip(t *testing.T) {
	t.Parallel()
	r := &OpenBaoKubernetesAuthRole{}
	require.False(t, r.IsBaoWritten())
	r.MarkBaoWritten()
	require.True(t, r.IsBaoWritten())
}

func TestKAER_BoundNamespaces_ReturnsCopy(t *testing.T) {
	t.Parallel()
	r := &OpenBaoKubernetesAuthRole{}
	r.SetInternalNamespaces([]string{"a", "b"})

	got := r.BoundNamespaces()
	require.Equal(t, []string{"a", "b"}, got)

	// Mutating the returned slice must not poison the internal state.
	got[0] = "tainted"
	require.Equal(t, []string{"a", "b"}, r.BoundNamespaces())
}

func TestKAER_PrepareInternalValues_LiteralListPath(t *testing.T) {
	t.Parallel()
	r := &OpenBaoKubernetesAuthRole{}
	r.Spec.TargetNamespaces.TargetNamespaces = []string{"ns-a", "ns-b"}

	require.NoError(t, r.PrepareInternalValues(context.Background(), r))
	require.Equal(t, []string{"ns-a", "ns-b"}, r.BoundNamespaces())
}

func TestKAER_PrepareInternalValues_SelectorPathReadsKubeClientFromCtx(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))

	matching := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "team-a-app", Labels: map[string]string{"tenant": "team-a"}},
	}
	other := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "team-b-app", Labels: map[string]string{"tenant": "team-b"}},
	}
	cl := crfake.NewClientBuilder().WithScheme(scheme).WithObjects(matching, other).Build()

	r := &OpenBaoKubernetesAuthRole{}
	r.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "team-a"}}

	//nolint:staticcheck // upstream-VCO key contract
	ctx := context.WithValue(context.Background(), "kubeClient", cl)
	require.NoError(t, r.PrepareInternalValues(ctx, r))
	require.Equal(t, []string{"team-a-app"}, r.BoundNamespaces())
}

func TestKAER_PrepareInternalValues_SelectorMatchesNothingWritesPlaceholder(t *testing.T) {
	// Bao rejects an empty bound list; upstream uses a sentinel so the
	// role write succeeds. When matching namespaces appear, the watch
	// fires and the role rebinds.
	t.Parallel()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	cl := crfake.NewClientBuilder().WithScheme(scheme).Build()

	r := &OpenBaoKubernetesAuthRole{}
	r.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "nobody"}}

	//nolint:staticcheck // upstream-VCO key contract
	ctx := context.WithValue(context.Background(), "kubeClient", cl)
	require.NoError(t, r.PrepareInternalValues(ctx, r))
	require.Equal(t, []string{NoNamespacePlaceholder}, r.BoundNamespaces())
}

func TestKAER_PrepareInternalValues_MissingKubeClientErrors(t *testing.T) {
	t.Parallel()
	r := &OpenBaoKubernetesAuthRole{}
	r.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"k": "v"}}

	err := r.PrepareInternalValues(context.Background(), r)
	require.Error(t, err)
	require.Contains(t, err.Error(), "kubeClient")
}

func TestKAER_PrepareInternalValues_PropagatesListError(t *testing.T) {
	t.Parallel()
	wrapErr := errors.New("simulated apiserver outage")

	r := &OpenBaoKubernetesAuthRole{}
	r.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"k": "v"}}

	//nolint:staticcheck // upstream-VCO key contract
	ctx := context.WithValue(context.Background(), "kubeClient", &erroringKubeClient{err: wrapErr})
	err := r.PrepareInternalValues(ctx, r)
	require.Error(t, err)
	require.ErrorIs(t, err, wrapErr)
}

// erroringKubeClient is a minimal client.Client whose List always errors.
type erroringKubeClient struct {
	client.Client
	err error
}

func (e *erroringKubeClient) List(_ context.Context, _ client.ObjectList, _ ...client.ListOption) error {
	return e.err
}
