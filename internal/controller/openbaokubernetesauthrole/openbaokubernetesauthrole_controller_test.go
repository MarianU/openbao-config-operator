package openbaokubernetesauthrole

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

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

// envtest namespace + auth-mount name reused across cases. Bare literals
// repeated 3+ times trip goconst.
const (
	envtestNS        = "default"
	defaultAuthMount = "kubernetes"
)

// Test-only stable UID literals — extracted to satisfy goconst.
const (
	uidA = "uid-a"
	uidB = "uid-b"
)

// ---- fake bao ----

// fakeBao implements baoclient.Client with in-memory role state, keyed
// by (openbaoNamespace, authMount, roleName) so bao's namespace
// isolation is modeled correctly. The OpenBaoKubernetesAuthRole
// controller doesn't touch policies, so those methods stub to noops.
type fakeBao struct {
	// roles keyed as "<openbaoNs>|<authMount>|<roleName>".
	roles map[string]baoclient.K8sRoleSpec

	// Error injection.
	roleUpsertErr error
	roleGetErr    error
	roleDeleteErr error

	// Call counters.
	roleUpserts, roleGets, roleDeletes int
}

func newFakeBao() *fakeBao {
	return &fakeBao{roles: map[string]baoclient.K8sRoleSpec{}}
}

func roleKey(ns, authMount, roleName string) string {
	return ns + "|" + authMount + "|" + roleName
}

func (f *fakeBao) CheckKVv2Mount(ctx context.Context, mount string, opts ...baoclient.CallOption) (bool, error) {
	return true, nil
}

func (f *fakeBao) UpsertPolicy(ctx context.Context, name, rules string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetPolicy(ctx context.Context, name string, opts ...baoclient.CallOption) (string, error) {
	return "", baoclient.ErrNotFound
}
func (f *fakeBao) DeletePolicy(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}

func (f *fakeBao) UpsertK8sRole(ctx context.Context, authMount, roleName string, spec baoclient.K8sRoleSpec, opts ...baoclient.CallOption) error {
	f.roleUpserts++
	if f.roleUpsertErr != nil {
		return f.roleUpsertErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	f.roles[roleKey(ns, authMount, roleName)] = spec
	return nil
}
func (f *fakeBao) GetK8sRole(ctx context.Context, authMount, roleName string, opts ...baoclient.CallOption) (*baoclient.K8sRole, error) {
	f.roleGets++
	if f.roleGetErr != nil {
		return nil, f.roleGetErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	spec, ok := f.roles[roleKey(ns, authMount, roleName)]
	if !ok {
		return nil, baoclient.ErrNotFound
	}
	return &baoclient.K8sRole{
		Name:                          roleName,
		Policies:                      spec.Policies,
		BoundServiceAccountNames:      spec.BoundServiceAccountNames,
		BoundServiceAccountNamespaces: spec.BoundServiceAccountNamespaces,
		Audience:                      spec.Audience,
		AliasNameSource:               spec.AliasNameSource,
		TokenBoundCIDRs:               spec.TokenBoundCIDRs,
		TokenTTL:                      spec.TokenTTL,
		TokenMaxTTL:                   spec.TokenMaxTTL,
		TokenExplicitMaxTTL:           spec.TokenExplicitMaxTTL,
		TokenNoDefaultPolicy:          spec.TokenNoDefaultPolicy,
		TokenNumUses:                  spec.TokenNumUses,
		TokenPeriod:                   spec.TokenPeriod,
		TokenType:                     spec.TokenType,
		Renewable:                     spec.Renewable,
	}, nil
}
func (f *fakeBao) DeleteK8sRole(ctx context.Context, authMount, roleName string, opts ...baoclient.CallOption) error {
	f.roleDeletes++
	if f.roleDeleteErr != nil {
		return f.roleDeleteErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	delete(f.roles, roleKey(ns, authMount, roleName))
	return nil
}

// Mount-lifecycle stubs — KAER controller's tests don't exercise these
// paths, but the fake must satisfy the full baoclient.Client interface.
func (f *fakeBao) EnableSecretEngine(ctx context.Context, mount string, spec baoclient.SecretEngineMountSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) TuneSecretEngine(ctx context.Context, mount string, spec baoclient.SecretEngineMountSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetSecretEngineMount(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.SecretEngineMount, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DisableSecretEngineMount(ctx context.Context, mount string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) DisableAuthMount(ctx context.Context, mount string, opts ...baoclient.CallOption) error {
	return nil
}

// AuthMethod stubs — this controller does not exercise sys/auth tune.
func (f *fakeBao) EnableAuthMethod(ctx context.Context, mount string, spec baoclient.AuthMethodMountSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) TuneAuthMethod(ctx context.Context, mount string, spec baoclient.AuthMethodMountSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetAuthMethod(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.AuthMethodMount, error) {
	return nil, baoclient.ErrNotFound
}

func (f *fakeBao) CreateNamespace(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetNamespace(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.Namespace, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteNamespace(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}

func (f *fakeBao) GenerateRootPKI(ctx context.Context, mount string, in baoclient.PKIRootGenerateInput, opts ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	return nil, baoclient.ErrNotFound
}

// Intermediate-CA stubs — these controllers do not exercise the intermediate flow.
func (f *fakeBao) GenerateIntermediateCSR(ctx context.Context, mount string, in baoclient.PKIIntermediateGenerateInput, opts ...baoclient.CallOption) (string, error) {
	return "", baoclient.ErrNotFound
}
func (f *fakeBao) SignIntermediate(ctx context.Context, rootMount, csr string, in baoclient.PKISignIntermediateInput, opts ...baoclient.CallOption) (string, error) {
	return "", baoclient.ErrNotFound
}
func (f *fakeBao) SetSignedIntermediate(ctx context.Context, mount, certificate string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ListPKIKeys(ctx context.Context, mount string, opts ...baoclient.CallOption) ([]string, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) ReadPKICA(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WritePKIURLs(ctx context.Context, mount string, in baoclient.PKIURLsInput, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadPKIURLs(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.PKIURLsInput, error) {
	return &baoclient.PKIURLsInput{}, nil
}

func (f *fakeBao) WritePKIRole(ctx context.Context, mount, name string, spec baoclient.PKIRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadPKIRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.PKIRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeletePKIRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return nil
}

// Identity stubs — this controller does not exercise the identity API.
func (f *fakeBao) WriteIdentityGroup(ctx context.Context, spec baoclient.IdentityGroupSpec, opts ...baoclient.CallOption) (*baoclient.IdentityGroup, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) ReadIdentityGroup(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.IdentityGroup, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityGroup(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteIdentityGroupAlias(ctx context.Context, spec baoclient.IdentityGroupAliasSpec, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) ReadIdentityGroupAliasByID(ctx context.Context, id string, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) FindIdentityGroupAlias(ctx context.Context, name, mountAccessor string, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityGroupAliasByID(ctx context.Context, id string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteIdentityTokenRole(ctx context.Context, name string, spec baoclient.IdentityTokenRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadIdentityTokenRole(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.IdentityTokenRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityTokenRole(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}

// ---- helpers ----

func buildKAERReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *OpenBaoKubernetesAuthRoleReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoKubernetesAuthRole{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoKubernetesAuthRole]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoKubernetesAuthRoleFinalizer,
		Handlers:      OpenBaoKubernetesAuthRoleHandlers(cl, fb),
	}
	return &OpenBaoKubernetesAuthRoleReconciler{VaultResource: base}
}

func toClientObjects(in []runtime.Object) []client.Object {
	out := make([]client.Object, 0, len(in))
	for _, o := range in {
		if co, ok := o.(client.Object); ok {
			out = append(out, co)
		}
	}
	return out
}

func sampleKAER(name string) *v1alpha1.OpenBaoKubernetesAuthRole {
	r := &v1alpha1.OpenBaoKubernetesAuthRole{}
	r.Name = name
	r.Namespace = envtestNS
	r.Spec.Path = defaultAuthMount
	r.Spec.Policies = []string{"editor"}
	r.Spec.TargetServiceAccounts = []string{"default"}
	r.Spec.TargetNamespaces.TargetNamespaces = []string{"team-a"}
	return r
}

func sampleKAERIn(ns, name string) *v1alpha1.OpenBaoKubernetesAuthRole {
	r := sampleKAER(name)
	r.Namespace = ns
	return r
}

func reconcileKAER(t *testing.T, r *OpenBaoKubernetesAuthRoleReconciler, ns, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getKAER(t *testing.T, r *OpenBaoKubernetesAuthRoleReconciler, ns, name string) *v1alpha1.OpenBaoKubernetesAuthRole {
	t.Helper()
	var k v1alpha1.OpenBaoKubernetesAuthRole
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &k))
	return &k
}

func kaerReadyCond(t *testing.T, k *v1alpha1.OpenBaoKubernetesAuthRole) *metav1.Condition {
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

	reconcileKAER(t, r, envtestNS, k.Name) // finalizer add
	got := getKAER(t, r, envtestNS, k.Name)
	require.Contains(t, got.Finalizers, OpenBaoKubernetesAuthRoleFinalizer)

	reconcileKAER(t, r, envtestNS, k.Name) // initial write
	require.Equal(t, 1, fb.roleUpserts, "bao role should be upserted once on create")
	stored, ok := fb.roles[roleKey("", defaultAuthMount, "team-a-reader")]
	require.True(t, ok, "bao role state should contain the new role")
	require.Equal(t, []string{"editor"}, stored.Policies)
	require.Equal(t, []string{"default"}, stored.BoundServiceAccountNames)
	require.Equal(t, []string{"team-a"}, stored.BoundServiceAccountNamespaces)

	cond := kaerReadyCond(t, getKAER(t, r, envtestNS, k.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
	require.Equal(t, resource.ReasonReconciled, cond.Reason)
}

func TestKAER_EditPath_RewritesOnPolicyChange(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	k := sampleKAER("editable")
	r := buildKAERReconciler(t, fb, k)

	reconcileKAER(t, r, envtestNS, k.Name)
	reconcileKAER(t, r, envtestNS, k.Name)
	require.Equal(t, 1, fb.roleUpserts)

	cur := getKAER(t, r, envtestNS, k.Name)
	cur.Spec.Policies = []string{"editor", "viewer"}
	require.NoError(t, r.Update(context.Background(), cur))

	reconcileKAER(t, r, envtestNS, k.Name)
	require.Equal(t, 2, fb.roleUpserts, "policy change should drive a re-upsert")
	stored := fb.roles[roleKey("", defaultAuthMount, "editable")]
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

	reconcileKAER(t, r, envtestNS, k.Name)
	reconcileKAER(t, r, envtestNS, k.Name)
	require.Equal(t, 1, fb.roleUpserts)

	// Simulate bao returning the bound list in a different order.
	stored := fb.roles[roleKey("", defaultAuthMount, "ordered")]
	stored.BoundServiceAccountNamespaces = []string{"c", "a", "b"}
	fb.roles[roleKey("", defaultAuthMount, "ordered")] = stored

	reconcileKAER(t, r, envtestNS, k.Name)
	require.Equal(t, 1, fb.roleUpserts, "reorder-only drift must not trigger a re-upsert")
}

// CLAUDE.md primitive checklist: drift comparator must normalize order
// on every list-shaped field where bao's read order is not guaranteed.
// bound_service_account_names, token_policies, and token_bound_cidrs
// are all set-semantic on bao's side and risk the same write-storm.
func TestKAER_DriftCorrection_NoSpuriousWriteOnOtherListReorders(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		setup  func(k *v1alpha1.OpenBaoKubernetesAuthRole)
		mutate func(stored *baoclient.K8sRoleSpec)
	}{
		{
			name: "bound-service-account-names",
			setup: func(k *v1alpha1.OpenBaoKubernetesAuthRole) {
				k.Spec.TargetServiceAccounts = []string{"sa-a", "sa-b", "sa-c"}
			},
			mutate: func(s *baoclient.K8sRoleSpec) {
				s.BoundServiceAccountNames = []string{"sa-c", "sa-a", "sa-b"}
			},
		},
		{
			name: "token-policies",
			setup: func(k *v1alpha1.OpenBaoKubernetesAuthRole) {
				k.Spec.Policies = []string{"editor", "viewer", "auditor"}
			},
			mutate: func(s *baoclient.K8sRoleSpec) {
				s.Policies = []string{"auditor", "editor", "viewer"}
			},
		},
		{
			name: "token-bound-cidrs",
			setup: func(k *v1alpha1.OpenBaoKubernetesAuthRole) {
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

			reconcileKAER(t, r, envtestNS, k.Name)
			reconcileKAER(t, r, envtestNS, k.Name)
			require.Equal(t, 1, fb.roleUpserts)

			stored := fb.roles[roleKey("", defaultAuthMount, k.Name)]
			tc.mutate(&stored)
			fb.roles[roleKey("", defaultAuthMount, k.Name)] = stored

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
// desired side, or every reconcile sees false drift and re-upserts.
func TestKAER_DriftCorrection_NoSpuriousWriteWhenBaoEchoesDefaultsForUnsetPointerFields(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	k := sampleKAER("default-echo")
	r := buildKAERReconciler(t, fb, k)

	reconcileKAER(t, r, envtestNS, k.Name)
	reconcileKAER(t, r, envtestNS, k.Name)
	require.Equal(t, 1, fb.roleUpserts)

	stored := fb.roles[roleKey("", defaultAuthMount, "default-echo")]
	zero := 0
	falseFlag := false
	stored.TokenNumUses = &zero
	stored.TokenNoDefaultPolicy = &falseFlag
	fb.roles[roleKey("", defaultAuthMount, "default-echo")] = stored

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

	reconcileKAER(t, r, envtestNS, k.Name)
	reconcileKAER(t, r, envtestNS, k.Name)
	require.Equal(t, 1, fb.roleUpserts)

	cur := getKAER(t, r, envtestNS, k.Name)
	require.NoError(t, r.Delete(context.Background(), cur))

	reconcileKAER(t, r, envtestNS, k.Name)
	require.Equal(t, 1, fb.roleDeletes, "BaoDelete must run once on terminating CR with baoWritten=true")
	_, stillThere := fb.roles[roleKey("", defaultAuthMount, "to-delete")]
	require.False(t, stillThere)

	err := r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: k.Name}, &v1alpha1.OpenBaoKubernetesAuthRole{})
	require.True(t, apierrors.IsNotFound(err))
}

// Regression for the wasEverReady → status.baoWritten structural fix.
func TestKAER_DeletePath_NeverWritten_SkipsBaoDelete(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	k := sampleKAER("never-written")
	// Force IsValid to reject by setting both targetNamespaces fields.
	k.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"k": "v"}}
	r := buildKAERReconciler(t, fb, k)

	reconcileKAER(t, r, envtestNS, k.Name)
	reconcileKAER(t, r, envtestNS, k.Name)
	require.Equal(t, 0, fb.roleUpserts)

	cur := getKAER(t, r, envtestNS, k.Name)
	cond := kaerReadyCond(t, cur)
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonInvalid, cond.Reason)

	require.NoError(t, r.Delete(context.Background(), cur))
	reconcileKAER(t, r, envtestNS, k.Name)

	require.Equal(t, 0, fb.roleDeletes, "BaoDelete must be skipped when status.baoWritten=false")
	require.True(t, apierrors.IsNotFound(
		r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: k.Name}, &v1alpha1.OpenBaoKubernetesAuthRole{})))
}

// ---- name collision ----

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

	reconcileKAER(t, r, "ns-a", "auth-role")
	reconcileKAER(t, r, "ns-a", "auth-role")
	require.Equal(t, 1, fb.roleUpserts)

	reconcileKAER(t, r, "ns-b", "auth-role")
	res := reconcileKAER(t, r, "ns-b", "auth-role")
	require.Equal(t, resource.PeriodicInterval, res.RequeueAfter,
		"collision is a stable state — loser should requeue at PeriodicInterval, not ErrorBackoff")
	require.Equal(t, 1, fb.roleUpserts, "newer (loser) must not have written")

	stored := fb.roles[roleKey("", defaultAuthMount, "auth-role")]
	require.Equal(t, []string{"editor"}, stored.Policies, "older's policies must remain")

	loser := getKAER(t, r, "ns-b", "auth-role")
	cond := kaerReadyCond(t, loser)
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)
	require.Contains(t, cond.Message, "ns-a/auth-role")
}

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

// Two CRs with the same metadata.name on different mounts target
// different bao paths and must NOT collide.
func TestKAER_NameCollision_DifferentPathDoesNotCollide(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	a := sampleKAERIn("ns-a", "shared-name")
	a.UID = uidA
	a.Spec.Path = defaultAuthMount

	b := sampleKAERIn("ns-b", "shared-name")
	b.UID = uidB
	b.Spec.Path = "kubernetes-other-cluster"

	r := buildKAERReconciler(t, fb, a, b)

	reconcileKAER(t, r, "ns-a", "shared-name")
	reconcileKAER(t, r, "ns-a", "shared-name")
	reconcileKAER(t, r, "ns-b", "shared-name")
	reconcileKAER(t, r, "ns-b", "shared-name")

	require.Equal(t, 2, fb.roleUpserts, "distinct bao paths → both writes succeed")
	require.Contains(t, fb.roles, roleKey("", defaultAuthMount, "shared-name"))
	require.Contains(t, fb.roles, roleKey("", "kubernetes-other-cluster", "shared-name"))
}

// New for OpenBaoKubernetesAuthRole: same path+name in different OpenBao
// namespaces is not a collision because bao stores them as separate
// objects scoped by X-Vault-Namespace. The collision check must compare
// the (path, OpenBaoNamespace) tuple, not just path.
func TestKAER_NameCollision_SameNameDifferentOpenBaoNamespaceDoesNotCollide(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	a := sampleKAERIn("ns-a", "auth-role")
	a.UID = uidA
	a.Spec.OpenBaoNamespace = "acme/"

	b := sampleKAERIn("ns-b", "auth-role")
	b.UID = uidB
	b.Spec.OpenBaoNamespace = "globex/"

	r := buildKAERReconciler(t, fb, a, b)

	reconcileKAER(t, r, "ns-a", "auth-role")
	reconcileKAER(t, r, "ns-a", "auth-role")
	reconcileKAER(t, r, "ns-b", "auth-role")
	reconcileKAER(t, r, "ns-b", "auth-role")

	require.Equal(t, 2, fb.roleUpserts, "different OpenBao namespaces → both writes succeed")

	condA := kaerReadyCond(t, getKAER(t, r, "ns-a", "auth-role"))
	require.NotNil(t, condA)
	require.Equal(t, metav1.ConditionTrue, condA.Status, "ns-a (acme/) should be Ready=True")

	condB := kaerReadyCond(t, getKAER(t, r, "ns-b", "auth-role"))
	require.NotNil(t, condB)
	require.Equal(t, metav1.ConditionTrue, condB.Status, "ns-b (globex/) should be Ready=True")

	require.Contains(t, fb.roles, roleKey("acme/", defaultAuthMount, "auth-role"))
	require.Contains(t, fb.roles, roleKey("globex/", defaultAuthMount, "auth-role"))
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

	reconcileKAER(t, r, envtestNS, k.Name)
	res := reconcileKAER(t, r, envtestNS, k.Name)

	require.Equal(t, 30*time.Second, res.RequeueAfter)
	cond := kaerReadyCond(t, getKAER(t, r, envtestNS, k.Name))
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

	reconcileKAER(t, r, envtestNS, k.Name)
	res := reconcileKAER(t, r, envtestNS, k.Name)

	require.Equal(t, 30*time.Second, res.RequeueAfter)
	cond := kaerReadyCond(t, getKAER(t, r, envtestNS, k.Name))
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

	k := &v1alpha1.OpenBaoKubernetesAuthRole{}
	k.Name = "team-a-selector"
	k.Namespace = envtestNS
	k.Spec.Path = defaultAuthMount
	k.Spec.Policies = []string{"editor"}
	k.Spec.TargetServiceAccounts = []string{"default"}
	k.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "team-a"}}

	r := buildKAERReconciler(t, fb, k, matchA, matchB, other)

	reconcileKAER(t, r, envtestNS, k.Name)
	reconcileKAER(t, r, envtestNS, k.Name)
	require.Equal(t, 1, fb.roleUpserts)

	stored := fb.roles[roleKey("", defaultAuthMount, "team-a-selector")]
	require.ElementsMatch(t, []string{"team-a-app", "team-a-api"}, stored.BoundServiceAccountNamespaces,
		"resolved selector must bind only the matching namespaces")
}

// Bao rejects an empty bound list. The sentinel keeps the role write
// succeeding when no namespace matches yet.
func TestKAER_SelectorMatchesNothing_WritesPlaceholder(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	k := &v1alpha1.OpenBaoKubernetesAuthRole{}
	k.Name = "no-match-yet"
	k.Namespace = envtestNS
	k.Spec.Path = defaultAuthMount
	k.Spec.Policies = []string{"editor"}
	k.Spec.TargetServiceAccounts = []string{"default"}
	k.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "nobody"}}

	r := buildKAERReconciler(t, fb, k)

	reconcileKAER(t, r, envtestNS, k.Name)
	reconcileKAER(t, r, envtestNS, k.Name)

	stored := fb.roles[roleKey("", defaultAuthMount, "no-match-yet")]
	require.Equal(t, []string{v1alpha1.NoNamespacePlaceholder}, stored.BoundServiceAccountNamespaces)
}

func TestKAER_NamespaceWatch_MapsLabelMatchToReconcileRequest(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	matcher := &v1alpha1.OpenBaoKubernetesAuthRole{}
	matcher.Name = "matcher"
	matcher.Namespace = envtestNS
	matcher.Spec.Path = defaultAuthMount
	matcher.Spec.Policies = []string{"p"}
	matcher.Spec.TargetServiceAccounts = []string{"default"}
	matcher.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"tenant": "team-a"}}

	literal := &v1alpha1.OpenBaoKubernetesAuthRole{}
	literal.Name = "literal"
	literal.Namespace = envtestNS
	literal.Spec.Path = defaultAuthMount
	literal.Spec.Policies = []string{"p"}
	literal.Spec.TargetServiceAccounts = []string{"default"}
	literal.Spec.TargetNamespaces.TargetNamespaces = []string{"some-ns"}

	nonMatcher := &v1alpha1.OpenBaoKubernetesAuthRole{}
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
	require.Equal(t, envtestNS, reqs[0].Namespace)
}

// checkRoleNameCollision lists all CRs cluster-wide; when that List
// fails, the helper wraps the error with resource.ErrInternal so that
// ClassifyErr (called by the base on BaoWrite errors) maps it to
// ReasonInternalError instead of ReasonBaoError. The fault is the k8s
// apiserver, not bao — paging on it as bao would mislead on-call.
func TestKAER_NameCollision_ListFailureSurfacesInternalError(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	k := sampleKAER("list-fails-collision")

	listErr := errors.New("simulated apiserver outage during collision check")
	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(k).
		WithStatusSubresource(&v1alpha1.OpenBaoKubernetesAuthRole{}).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, isKAERList := list.(*v1alpha1.OpenBaoKubernetesAuthRoleList); isKAERList {
					return listErr
				}
				return c.List(ctx, list, opts...)
			},
		}).
		Build()

	fb := newFakeBao()
	base := &resource.VaultResource[*v1alpha1.OpenBaoKubernetesAuthRole]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoKubernetesAuthRoleFinalizer,
		Handlers:      OpenBaoKubernetesAuthRoleHandlers(cl, fb),
	}
	r := &OpenBaoKubernetesAuthRoleReconciler{VaultResource: base}

	reconcileKAER(t, r, envtestNS, k.Name)
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

func TestKAER_NamespaceListFails_ReadyReasonInternalError(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	k := &v1alpha1.OpenBaoKubernetesAuthRole{}
	k.Name = "list-fails"
	k.Namespace = envtestNS
	k.Spec.Path = defaultAuthMount
	k.Spec.Policies = []string{"editor"}
	k.Spec.TargetServiceAccounts = []string{"default"}
	// Selector with an invalid expression — LabelSelectorAsSelector will
	// reject it, exercising the error path without injecting failures.
	k.Spec.TargetNamespaces.TargetNamespaceSelector = &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "tenant", Operator: "BogusOperator", Values: []string{"team-a"},
		}},
	}

	r := buildKAERReconciler(t, fb, k)

	reconcileKAER(t, r, envtestNS, k.Name)
	res := reconcileKAER(t, r, envtestNS, k.Name)
	require.Equal(t, 30*time.Second, res.RequeueAfter, "PrepareInternalValues failure should requeue with error backoff")

	cond := kaerReadyCond(t, getKAER(t, r, envtestNS, k.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonInternalError, cond.Reason,
		"PrepareInternalValues failures must classify as InternalError, not BaoError")
}

// Cert auth + JWT/OIDC stubs — this controller does not exercise them.
func (f *fakeBao) WriteCertAuthConfig(ctx context.Context, mount string, spec baoclient.CertAuthConfigSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadCertAuthConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.CertAuthConfigSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WriteCertAuthRole(ctx context.Context, mount, name string, spec baoclient.CertAuthRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadCertAuthRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.CertAuthRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteCertAuthRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteJWTOIDCConfig(ctx context.Context, mount string, spec baoclient.JWTOIDCConfigSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadJWTOIDCConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.JWTOIDCConfigSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WriteK8sAuthConfig(ctx context.Context, mount string, spec baoclient.K8sAuthConfigSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadK8sAuthConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.K8sAuthConfigSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WriteJWTOIDCRole(ctx context.Context, mount, name string, spec baoclient.JWTOIDCRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadJWTOIDCRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.JWTOIDCRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteJWTOIDCRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteTransitKey(ctx context.Context, mount, name string, spec baoclient.TransitKeySpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadTransitKey(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.TransitKeyInfo, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) UpdateTransitKeyConfig(ctx context.Context, mount, name string, spec baoclient.TransitKeySpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) DeleteTransitKey(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return nil
}
