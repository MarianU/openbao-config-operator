package vco

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	vcov1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/vco/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

// Test-only stable UID literals — extracted to satisfy goconst across
// multiple collision cases that need predictable identities.
const (
	uidA = "uid-a"
	uidB = "uid-b"
)

// ---- helpers ----

func buildKAERReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *KubernetesAuthEngineRoleReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, vcov1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&vcov1alpha1.KubernetesAuthEngineRole{}).
		Build()

	base := &resource.VaultResource[*vcov1alpha1.KubernetesAuthEngineRole]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: KubernetesAuthEngineRoleFinalizer,
		Handlers:      KubernetesAuthEngineRoleHandlers(cl, fb),
	}
	return &KubernetesAuthEngineRoleReconciler{VaultResource: base}
}

func sampleKAER(name string) *vcov1alpha1.KubernetesAuthEngineRole {
	r := &vcov1alpha1.KubernetesAuthEngineRole{}
	r.Name = name
	r.Namespace = envtestNS
	r.Spec.Path = defaultAuthMount
	r.Spec.Policies = []string{"editor"}
	r.Spec.TargetServiceAccounts = []string{"default"}
	r.Spec.TargetNamespaces.TargetNamespaces = []string{"team-a"}
	return r
}

func sampleKAERIn(ns, name string) *vcov1alpha1.KubernetesAuthEngineRole {
	r := sampleKAER(name)
	r.Namespace = ns
	return r
}

func reconcileKAER(t *testing.T, r *KubernetesAuthEngineRoleReconciler, ns, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getKAER(t *testing.T, r *KubernetesAuthEngineRoleReconciler, ns, name string) *vcov1alpha1.KubernetesAuthEngineRole {
	t.Helper()
	var k vcov1alpha1.KubernetesAuthEngineRole
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &k))
	return &k
}

func kaerReadyCond(t *testing.T, k *vcov1alpha1.KubernetesAuthEngineRole) *metav1.Condition {
	t.Helper()
	for i := range k.Status.Conditions {
		if k.Status.Conditions[i].Type == resource.ConditionReady {
			return &k.Status.Conditions[i]
		}
	}
	return nil
}

// ---- create / edit / drift / delete ----

func TestKAER_CreatePath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	k := sampleKAER("team-a-reader")
	r := buildKAERReconciler(t, fb, k)

	reconcileKAER(t, r, "default", k.Name) // finalizer add
	got := getKAER(t, r, "default", k.Name)
	require.Contains(t, got.Finalizers, KubernetesAuthEngineRoleFinalizer)

	reconcileKAER(t, r, "default", k.Name) // initial write
	require.Equal(t, 1, fb.roleUpserts, "bao role should be upserted once on create")
	stored, ok := fb.roles[roleKey("kubernetes", "team-a-reader")]
	require.True(t, ok, "bao role state should contain the new role")
	require.Equal(t, []string{"editor"}, stored.Policies)
	require.Equal(t, []string{"default"}, stored.BoundServiceAccountNames)
	require.Equal(t, []string{"team-a"}, stored.BoundServiceAccountNamespaces)

	cond := kaerReadyCond(t, getKAER(t, r, "default", k.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
	require.Equal(t, resource.ReasonReconciled, cond.Reason)
}

func TestKAER_EditPath_RewritesOnPolicyChange(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	k := sampleKAER("editable")
	r := buildKAERReconciler(t, fb, k)

	reconcileKAER(t, r, "default", k.Name) // finalizer
	reconcileKAER(t, r, "default", k.Name) // write
	require.Equal(t, 1, fb.roleUpserts)

	// Edit spec.policies on the CR.
	cur := getKAER(t, r, "default", k.Name)
	cur.Spec.Policies = []string{"editor", "viewer"}
	require.NoError(t, r.Update(context.Background(), cur))

	reconcileKAER(t, r, "default", k.Name)
	require.Equal(t, 2, fb.roleUpserts, "policy change should drive a re-upsert")
	stored := fb.roles[roleKey("kubernetes", "editable")]
	require.ElementsMatch(t, []string{"editor", "viewer"}, stored.Policies)
}

// Bao does not guarantee a stable order on bound_service_account_namespaces
// reads. The drift comparator must tolerate reorderings; otherwise every
// 5-minute periodic reconcile re-upserts the role unnecessarily.
func TestKAER_DriftCorrection_NoSpuriousWriteOnNamespaceReorder(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	k := sampleKAER("ordered")
	k.Spec.TargetNamespaces.TargetNamespaces = []string{"a", "b", "c"}
	r := buildKAERReconciler(t, fb, k)

	reconcileKAER(t, r, envtestNS, k.Name) // finalizer
	reconcileKAER(t, r, envtestNS, k.Name) // write
	require.Equal(t, 1, fb.roleUpserts)

	// Simulate bao returning the bound list in a different order.
	stored := fb.roles[roleKey(defaultAuthMount, "ordered")]
	stored.BoundServiceAccountNamespaces = []string{"c", "a", "b"}
	fb.roles[roleKey(defaultAuthMount, "ordered")] = stored

	reconcileKAER(t, r, envtestNS, k.Name)
	require.Equal(t, 1, fb.roleUpserts, "reorder-only drift must not trigger a re-upsert")
}

// CLAUDE.md primitive checklist: drift comparator must normalize order
// on every list-shaped field where bao's read order is not guaranteed
// equal to the write order. bound_service_account_names, token_policies,
// and token_bound_cidrs are all set-semantic on bao's side and risk the
// same write-storm class as bound_service_account_namespaces.
func TestKAER_DriftCorrection_NoSpuriousWriteOnOtherListReorders(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		setup  func(k *vcov1alpha1.KubernetesAuthEngineRole)
		mutate func(stored *baoclient.K8sRoleSpec)
	}{
		{
			name: "bound-service-account-names",
			setup: func(k *vcov1alpha1.KubernetesAuthEngineRole) {
				k.Spec.TargetServiceAccounts = []string{"sa-a", "sa-b", "sa-c"}
			},
			mutate: func(s *baoclient.K8sRoleSpec) {
				s.BoundServiceAccountNames = []string{"sa-c", "sa-a", "sa-b"}
			},
		},
		{
			name: "token-policies",
			setup: func(k *vcov1alpha1.KubernetesAuthEngineRole) {
				k.Spec.Policies = []string{"editor", "viewer", "auditor"}
			},
			mutate: func(s *baoclient.K8sRoleSpec) {
				s.Policies = []string{"auditor", "editor", "viewer"}
			},
		},
		{
			name: "token-bound-cidrs",
			setup: func(k *vcov1alpha1.KubernetesAuthEngineRole) {
				k.Spec.TokenBoundCIDRs = []string{"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"}
			},
			mutate: func(s *baoclient.K8sRoleSpec) {
				s.TokenBoundCIDRs = []string{"172.16.0.0/12", "10.0.0.0/8", "192.168.0.0/16"}
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fb := newFakeBao()
			k := sampleKAER("reorder-" + tc.name)
			tc.setup(k)
			r := buildKAERReconciler(t, fb, k)

			reconcileKAER(t, r, envtestNS, k.Name) // finalizer
			reconcileKAER(t, r, envtestNS, k.Name) // write
			require.Equal(t, 1, fb.roleUpserts)

			stored := fb.roles[roleKey(defaultAuthMount, k.Name)]
			tc.mutate(&stored)
			fb.roles[roleKey(defaultAuthMount, k.Name)] = stored

			reconcileKAER(t, r, envtestNS, k.Name)
			require.Equal(t, 1, fb.roleUpserts,
				"reorder-only drift on %s must not trigger a re-upsert", tc.name)
		})
	}
}

// Real bao always echoes back the full role payload on read, including
// the default values for fields the upsert never set (token_num_uses=0,
// token_no_default_policy=false). The drift comparator's emit
// predicates must treat those defaults as equivalent to "unset" on the
// desired side, or every reconcile sees false drift and re-upserts —
// the classic 5-minute write storm.
//
// Existing fakeBao tests don't catch this because the fakeBao echoes
// the spec verbatim (nil pointers stay nil). This test mutates the
// stored role to simulate bao's default-fill behavior.
func TestKAER_DriftCorrection_NoSpuriousWriteWhenBaoEchoesDefaultsForUnsetPointerFields(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	// Sample CR leaves TokenNumUses and TokenNoDefaultPolicy unset
	// (nil pointers); both are the common case.
	k := sampleKAER("default-echo")
	r := buildKAERReconciler(t, fb, k)

	reconcileKAER(t, r, envtestNS, k.Name) // finalizer
	reconcileKAER(t, r, envtestNS, k.Name) // write
	require.Equal(t, 1, fb.roleUpserts)

	// Simulate bao filling in the default values on the read side.
	stored := fb.roles[roleKey(defaultAuthMount, "default-echo")]
	zero := 0
	falseFlag := false
	stored.TokenNumUses = &zero
	stored.TokenNoDefaultPolicy = &falseFlag
	fb.roles[roleKey(defaultAuthMount, "default-echo")] = stored

	// Two more reconciles. Each one would call BaoWrite if the drift
	// check saw a mismatch, so any re-upsert here is a regression.
	reconcileKAER(t, r, envtestNS, k.Name)
	reconcileKAER(t, r, envtestNS, k.Name)
	require.Equal(t, 1, fb.roleUpserts,
		"bao echoing default zero-values for unset pointer fields must not look like drift")
}

func TestKAER_DeletePath_BaoWrittenTrue_CallsDelete(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	k := sampleKAER("to-delete")
	r := buildKAERReconciler(t, fb, k)

	reconcileKAER(t, r, "default", k.Name) // finalizer
	reconcileKAER(t, r, "default", k.Name) // write
	require.Equal(t, 1, fb.roleUpserts)

	cur := getKAER(t, r, "default", k.Name)
	require.NoError(t, r.Delete(context.Background(), cur))

	reconcileKAER(t, r, "default", k.Name)
	require.Equal(t, 1, fb.roleDeletes, "BaoDelete must run once on terminating CR with baoWritten=true")
	_, stillThere := fb.roles[roleKey("kubernetes", "to-delete")]
	require.False(t, stillThere)

	err := r.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: k.Name}, &vcov1alpha1.KubernetesAuthEngineRole{})
	require.True(t, apierrors.IsNotFound(err))
}

// Regression for the wasEverReady → status.baoWritten structural fix.
// A CR that never wrote (e.g. IsValid rejected before BaoWrite) must
// release its finalizer without calling BaoDelete; otherwise primitives
// with strict delete endpoints would strand CRs in Terminating.
func TestKAER_DeletePath_NeverWritten_SkipsBaoDelete(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	k := sampleKAER("never-written")
	// Force IsValid to reject by setting both targetNamespaces fields.
	k.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"k": "v"}}
	r := buildKAERReconciler(t, fb, k)

	reconcileKAER(t, r, "default", k.Name) // finalizer
	reconcileKAER(t, r, "default", k.Name) // IsValid rejects → no BaoWrite
	require.Equal(t, 0, fb.roleUpserts)

	cur := getKAER(t, r, "default", k.Name)
	cond := kaerReadyCond(t, cur)
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonInvalid, cond.Reason)

	require.NoError(t, r.Delete(context.Background(), cur))
	reconcileKAER(t, r, "default", k.Name)

	require.Equal(t, 0, fb.roleDeletes, "BaoDelete must be skipped when status.baoWritten=false")
	require.True(t, apierrors.IsNotFound(
		r.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: k.Name}, &vcov1alpha1.KubernetesAuthEngineRole{})))
}

// ---- name collision ----

// Two CRs in different k8s namespaces sharing (spec.path, metadata.name)
// would silently overwrite each other on bao. The collision check
// arbitrates by older-CreationTimestamp + lex tiebreak.
func TestKAER_NameCollision_OlderWinsLoserRefuses(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	older := sampleKAERIn("ns-a", "auth-role")
	older.UID = "uid-older"
	older.CreationTimestamp = metav1.NewTime(time.Now().Add(-1 * time.Hour))

	newer := sampleKAERIn("ns-b", "auth-role")
	newer.UID = "uid-newer"
	newer.CreationTimestamp = metav1.NewTime(time.Now())
	newer.Spec.Policies = []string{"different-policy"}

	r := buildKAERReconciler(t, fb, older, newer)

	reconcileKAER(t, r, "ns-a", "auth-role") // finalizer
	reconcileKAER(t, r, "ns-a", "auth-role") // write
	require.Equal(t, 1, fb.roleUpserts)

	reconcileKAER(t, r, "ns-b", "auth-role") // finalizer
	res := reconcileKAER(t, r, "ns-b", "auth-role")
	require.Equal(t, 30*time.Second, res.RequeueAfter, "collision should retry with backoff")
	require.Equal(t, 1, fb.roleUpserts, "newer (loser) must not have written; older still owns the bao role")

	stored := fb.roles[roleKey("kubernetes", "auth-role")]
	require.Equal(t, []string{"editor"}, stored.Policies, "older's policies must remain")

	loser := getKAER(t, r, "ns-b", "auth-role")
	cond := kaerReadyCond(t, loser)
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)
	require.Contains(t, cond.Message, "ns-a/auth-role")
}

// Same instant on both CreationTimestamps → tie-break on lex order of
// <namespace>/<name>. "ns-a/auth-role" < "ns-b/auth-role" so ns-a wins.
// Without an explicit test the default branch in the collision switch
// would silently drift on a refactor.
func TestKAER_NameCollision_TimestampTieBrokenLexicographically(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	now := metav1.NewTime(time.Now())

	a := sampleKAERIn("ns-a", "auth-role")
	a.UID = uidA
	a.CreationTimestamp = now

	b := sampleKAERIn("ns-b", "auth-role")
	b.UID = uidB
	b.CreationTimestamp = now
	b.Spec.Policies = []string{"different-policy"}

	r := buildKAERReconciler(t, fb, a, b)

	reconcileKAER(t, r, "ns-a", "auth-role")
	reconcileKAER(t, r, "ns-a", "auth-role")
	require.Equal(t, 1, fb.roleUpserts, "ns-a (lex earlier) must write")

	reconcileKAER(t, r, "ns-b", "auth-role")
	reconcileKAER(t, r, "ns-b", "auth-role")
	require.Equal(t, 1, fb.roleUpserts, "ns-b (lex later) must NOT write")

	condB := kaerReadyCond(t, getKAER(t, r, "ns-b", "auth-role"))
	require.NotNil(t, condB)
	require.Equal(t, resource.ReasonNameCollision, condB.Reason)
	require.Contains(t, condB.Message, "ns-a/auth-role",
		"loser's message should name the lex-earlier winner")
}

// Regression-guard: KubernetesAuthEngineRole's bao identity is the FULL
// path auth/<mount>/role/<name>, not just the role name. Two CRs with
// the same metadata.name on different mounts target different bao paths
// and must NOT collide. Guards the per-mount collision scope against a
// refactor that compares only role names.
func TestKAER_NameCollision_DifferentPathDoesNotCollide(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	a := sampleKAERIn("ns-a", "shared-name")
	a.UID = uidA
	a.Spec.Path = "kubernetes"

	b := sampleKAERIn("ns-b", "shared-name")
	b.UID = uidB
	b.Spec.Path = "kubernetes-other-cluster"

	r := buildKAERReconciler(t, fb, a, b)

	reconcileKAER(t, r, "ns-a", "shared-name") // finalizer
	reconcileKAER(t, r, "ns-a", "shared-name") // write
	reconcileKAER(t, r, "ns-b", "shared-name") // finalizer
	reconcileKAER(t, r, "ns-b", "shared-name") // write

	require.Equal(t, 2, fb.roleUpserts, "distinct bao paths → both writes succeed")
	require.Contains(t, fb.roles, roleKey("kubernetes", "shared-name"))
	require.Contains(t, fb.roles, roleKey("kubernetes-other-cluster", "shared-name"))
}

// ---- error classification ----

func TestKAER_BaoForbidden(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.roleUpsertErr = &baoclient.StatusError{
		StatusCode: http.StatusForbidden,
		Inner:      errors.New("permission denied"),
	}
	k := sampleKAER("forbidden")
	r := buildKAERReconciler(t, fb, k)

	reconcileKAER(t, r, "default", k.Name) // finalizer
	res := reconcileKAER(t, r, "default", k.Name)

	require.Equal(t, 30*time.Second, res.RequeueAfter)
	cond := kaerReadyCond(t, getKAER(t, r, "default", k.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonForbidden, cond.Reason)
}

func TestKAER_BaoUnreachable(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.roleGetErr = errors.New("dial tcp 127.0.0.1:8200: connection refused")
	k := sampleKAER("unreachable")
	r := buildKAERReconciler(t, fb, k)

	reconcileKAER(t, r, "default", k.Name) // finalizer
	res := reconcileKAER(t, r, "default", k.Name)

	require.Equal(t, 30*time.Second, res.RequeueAfter)
	cond := kaerReadyCond(t, getKAER(t, r, "default", k.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonBaoError, cond.Reason)
}

// ---- selector / namespace watch ----

func TestKAER_SelectorMatchesNamespaces_BindsLiveSet(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	matchA := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a-app", Labels: map[string]string{"tenant": "team-a"}}}
	matchB := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a-api", Labels: map[string]string{"tenant": "team-a"}}}
	other := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-b", Labels: map[string]string{"tenant": "team-b"}}}

	k := &vcov1alpha1.KubernetesAuthEngineRole{}
	k.Name = "team-a-selector"
	k.Namespace = envtestNS
	k.Spec.Path = defaultAuthMount
	k.Spec.Policies = []string{"editor"}
	k.Spec.TargetServiceAccounts = []string{"default"}
	k.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "team-a"}}

	r := buildKAERReconciler(t, fb, k, matchA, matchB, other)

	reconcileKAER(t, r, "default", k.Name) // finalizer
	reconcileKAER(t, r, "default", k.Name) // write
	require.Equal(t, 1, fb.roleUpserts)

	stored := fb.roles[roleKey("kubernetes", "team-a-selector")]
	require.ElementsMatch(t, []string{"team-a-app", "team-a-api"}, stored.BoundServiceAccountNamespaces,
		"resolved selector must bind only the matching namespaces")
}

// Bao rejects an empty bound list. Upstream's sentinel keeps the role
// write succeeding when no namespace matches yet; once one appears the
// watch fires and the role rebinds.
func TestKAER_SelectorMatchesNothing_WritesPlaceholder(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	k := &vcov1alpha1.KubernetesAuthEngineRole{}
	k.Name = "no-match-yet"
	k.Namespace = envtestNS
	k.Spec.Path = defaultAuthMount
	k.Spec.Policies = []string{"editor"}
	k.Spec.TargetServiceAccounts = []string{"default"}
	k.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "nobody"}}

	r := buildKAERReconciler(t, fb, k)

	reconcileKAER(t, r, "default", k.Name) // finalizer
	reconcileKAER(t, r, "default", k.Name) // write

	stored := fb.roles[roleKey("kubernetes", "no-match-yet")]
	require.Equal(t, []string{vcov1alpha1.NoNamespacePlaceholder}, stored.BoundServiceAccountNamespaces)
}

func TestKAER_NamespaceWatch_MapsLabelMatchToReconcileRequest(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	matcher := &vcov1alpha1.KubernetesAuthEngineRole{}
	matcher.Name = "matcher"
	matcher.Namespace = envtestNS
	matcher.Spec.Path = defaultAuthMount
	matcher.Spec.Policies = []string{"p"}
	matcher.Spec.TargetServiceAccounts = []string{"default"}
	matcher.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "team-a"}}

	literal := &vcov1alpha1.KubernetesAuthEngineRole{}
	literal.Name = "literal"
	literal.Namespace = "default"
	literal.Spec.Path = "kubernetes"
	literal.Spec.Policies = []string{"p"}
	literal.Spec.TargetServiceAccounts = []string{"default"}
	literal.Spec.TargetNamespaces.TargetNamespaces = []string{"some-ns"}

	nonMatcher := &vcov1alpha1.KubernetesAuthEngineRole{}
	nonMatcher.Name = "nonmatch"
	nonMatcher.Namespace = envtestNS
	nonMatcher.Spec.Path = defaultAuthMount
	nonMatcher.Spec.Policies = []string{"p"}
	nonMatcher.Spec.TargetServiceAccounts = []string{"default"}
	nonMatcher.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "team-b"}}

	r := buildKAERReconciler(t, fb, matcher, literal, nonMatcher)

	changed := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a-app", Labels: map[string]string{"tenant": "team-a"}}}
	reqs := r.mapNamespaceToCRs(context.Background(), changed)

	require.Len(t, reqs, 1, "only the selector-matching CR should be enqueued")
	require.Equal(t, "matcher", reqs[0].Name)
	require.Equal(t, "default", reqs[0].Namespace)
}

// checkRoleNameCollision lists all KAERs cluster-wide; when that List
// fails, the helper wraps the error with resource.ErrInternal so that
// ClassifyErr (called by the base on BaoWrite errors) maps it to
// ReasonInternalError instead of ReasonBaoError. The fault is the k8s
// apiserver, not bao — paging on it as bao would mislead on-call.
//
// Without this test a refactor that drops the ErrInternal wrap would
// silently re-classify the failure as ReasonBaoError; the create-path
// and edit-path tests don't exercise this branch.
func TestKAER_NameCollision_ListFailureSurfacesInternalError(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, vcov1alpha1.AddToScheme(scheme))

	k := sampleKAER("list-fails-collision")

	// Inject a List failure ONLY when the listed object is the KAER
	// list (the collision check). Other List calls (e.g. namespace
	// resolution if the spec used a selector) must continue to work
	// so the test isolates the collision-check branch.
	listErr := errors.New("simulated apiserver outage during collision check")
	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(k).
		WithStatusSubresource(&vcov1alpha1.KubernetesAuthEngineRole{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, isKAERList := list.(*vcov1alpha1.KubernetesAuthEngineRoleList); isKAERList {
					return listErr
				}
				return c.List(ctx, list, opts...)
			},
		}).
		Build()

	fb := newFakeBao()
	base := &resource.VaultResource[*vcov1alpha1.KubernetesAuthEngineRole]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: KubernetesAuthEngineRoleFinalizer,
		Handlers:      KubernetesAuthEngineRoleHandlers(cl, fb),
	}
	r := &KubernetesAuthEngineRoleReconciler{VaultResource: base}

	reconcileKAER(t, r, envtestNS, k.Name) // finalizer add (List not yet called)
	res := reconcileKAER(t, r, envtestNS, k.Name)
	require.Equal(t, 30*time.Second, res.RequeueAfter,
		"collision-check List failure should requeue with error backoff, not block reconcile")

	require.Equal(t, 0, fb.roleUpserts,
		"BaoWrite must NOT proceed when the collision check failed — failing closed prevents silent overwrite")

	cond := kaerReadyCond(t, getKAER(t, r, envtestNS, k.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonInternalError, cond.Reason,
		"collision-check List failure must classify as InternalError, not BaoError")
	require.Contains(t, cond.Message, "simulated apiserver outage",
		"original error should be visible in the surfaced message")
}

// PrepareInternalValues failures must classify as InternalError, not
// BaoError — the fault is in the k8s apiserver, not bao. The base
// hardcodes ReasonInternalError for any PrepareInternalValues error
// (vaultresource.go); this test confirms that classification reaches
// the user-visible Ready condition end-to-end.
func TestKAER_NamespaceListFails_ReadyReasonInternalError(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	k := &vcov1alpha1.KubernetesAuthEngineRole{}
	k.Name = "list-fails"
	k.Namespace = envtestNS
	k.Spec.Path = defaultAuthMount
	k.Spec.Policies = []string{"editor"}
	k.Spec.TargetServiceAccounts = []string{"default"}
	// Selector with an invalid expression — LabelSelectorAsSelector will
	// reject it inside findSelectedNamespaceNames, exercising the error
	// path without needing to inject failures into the k8s client.
	k.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "tenant", Operator: "BogusOperator", Values: []string{"team-a"},
		}},
	}

	r := buildKAERReconciler(t, fb, k)

	reconcileKAER(t, r, "default", k.Name) // finalizer
	res := reconcileKAER(t, r, "default", k.Name)
	require.Equal(t, 30*time.Second, res.RequeueAfter, "PrepareInternalValues failure should requeue with error backoff")

	cond := kaerReadyCond(t, getKAER(t, r, "default", k.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonInternalError, cond.Reason,
		"PrepareInternalValues failures must classify as InternalError, not BaoError")
}
