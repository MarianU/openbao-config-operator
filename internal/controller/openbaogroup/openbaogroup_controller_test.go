package openbaogroup

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

const (
	envtestNS = "default"
	uidA      = "uid-a"
	uidB      = "uid-b"
	nsA       = "ns-a"
	nsB       = "ns-b"
)

// fakeBao models bao's identity-group surface in-memory keyed by
// (openbaoNamespace, name). Other Client methods are stubbed since
// the OpenBaoGroup controller touches none of them.
type fakeBao struct {
	groups map[string]*baoclient.IdentityGroup // key: ns|name
	nextID int

	// Error injection.
	writeErr  error
	readErr   error
	deleteErr error

	// Call counters.
	writes, reads, deletes int
}

func newFakeBao() *fakeBao {
	return &fakeBao{groups: map[string]*baoclient.IdentityGroup{}}
}

func groupKey(ns, name string) string { return ns + "|" + name }

// ---- minimal stubs for the rest of the Client interface ----

func (f *fakeBao) CheckKVv2Mount(ctx context.Context, mount string, opts ...baoclient.CallOption) (bool, error) {
	return true, nil
}
func (f *fakeBao) CheckAuthMount(ctx context.Context, mount string, opts ...baoclient.CallOption) (bool, error) {
	return true, nil
}
func (f *fakeBao) EnableAuthMount(ctx context.Context, mount, typ string, opts ...baoclient.CallOption) error {
	return nil
}
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
func (f *fakeBao) GetAuthMount(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.AuthMount, error) {
	return nil, baoclient.ErrNotFound
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
	return nil
}
func (f *fakeBao) GetK8sRole(ctx context.Context, authMount, roleName string, opts ...baoclient.CallOption) (*baoclient.K8sRole, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteK8sRole(ctx context.Context, authMount, roleName string, opts ...baoclient.CallOption) error {
	return nil
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

// ---- IdentityGroup surface (the one this fake actually models) ----

func (f *fakeBao) WriteIdentityGroup(ctx context.Context, spec baoclient.IdentityGroupSpec, opts ...baoclient.CallOption) (*baoclient.IdentityGroup, error) {
	f.writes++
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	id := spec.ID
	if id == "" {
		// Existing-by-name takes precedence so an upsert reuses the
		// already-stamped id rather than re-issuing.
		if existing, ok := f.groups[groupKey(ns, spec.Name)]; ok && existing != nil {
			id = existing.ID
		} else {
			f.nextID++
			id = "g-" + iToA(f.nextID)
		}
	}
	g := &baoclient.IdentityGroup{
		ID:              id,
		Name:            spec.Name,
		Type:            spec.Type,
		Policies:        append([]string(nil), spec.Policies...),
		MemberGroupIDs:  append([]string(nil), spec.MemberGroupIDs...),
		MemberEntityIDs: append([]string(nil), spec.MemberEntityIDs...),
		Metadata:        copyMap(spec.Metadata),
	}
	if g.Type == "" {
		g.Type = v1alpha1.GroupTypeInternal
	}
	f.groups[groupKey(ns, spec.Name)] = g
	return &baoclient.IdentityGroup{
		ID:              g.ID,
		Name:            g.Name,
		Type:            g.Type,
		Policies:        append([]string(nil), g.Policies...),
		MemberGroupIDs:  append([]string(nil), g.MemberGroupIDs...),
		MemberEntityIDs: append([]string(nil), g.MemberEntityIDs...),
		Metadata:        copyMap(g.Metadata),
	}, nil
}

func (f *fakeBao) ReadIdentityGroup(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.IdentityGroup, error) {
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	g, ok := f.groups[groupKey(ns, name)]
	if !ok {
		return nil, baoclient.ErrNotFound
	}
	return &baoclient.IdentityGroup{
		ID:              g.ID,
		Name:            g.Name,
		Type:            g.Type,
		Policies:        append([]string(nil), g.Policies...),
		MemberGroupIDs:  append([]string(nil), g.MemberGroupIDs...),
		MemberEntityIDs: append([]string(nil), g.MemberEntityIDs...),
		Metadata:        copyMap(g.Metadata),
	}, nil
}

func (f *fakeBao) DeleteIdentityGroup(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	f.deletes++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	ns := baoclient.NamespaceFromOpts(opts)
	delete(f.groups, groupKey(ns, name))
	return nil
}

func iToA(i int) string {
	if i == 0 {
		return "0"
	}
	const digits = "0123456789"
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = digits[i%10]
		i /= 10
	}
	return string(buf[pos:])
}

func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ---- harness ----

func buildReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *OpenBaoGroupReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoGroup{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoGroup]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoGroupFinalizer,
		Handlers:      OpenBaoGroupHandlers(cl, fb),
	}
	return &OpenBaoGroupReconciler{VaultResource: base}
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

func sampleGroup(name string) *v1alpha1.OpenBaoGroup {
	g := &v1alpha1.OpenBaoGroup{}
	g.Name = name
	g.Namespace = envtestNS
	return g
}

func reconcile(t *testing.T, r *OpenBaoGroupReconciler, ns, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getGroup(t *testing.T, r *OpenBaoGroupReconciler, ns, name string) *v1alpha1.OpenBaoGroup {
	t.Helper()
	var g v1alpha1.OpenBaoGroup
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &g))
	return &g
}

func readyCond(t *testing.T, g *v1alpha1.OpenBaoGroup) *metav1.Condition {
	t.Helper()
	for i := range g.Status.Conditions {
		if g.Status.Conditions[i].Type == resource.ConditionReady {
			return &g.Status.Conditions[i]
		}
	}
	return nil
}

// ---- create / drift / delete ----

func TestOpenBaoGroup_CreatePath_StampsGroupID(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	g := sampleGroup("team-a")
	g.Spec.Policies = []string{"reader"}
	r := buildReconciler(t, fb, g)

	reconcile(t, r, envtestNS, g.Name) // finalizer
	require.Contains(t, getGroup(t, r, envtestNS, g.Name).Finalizers, OpenBaoGroupFinalizer)

	res := reconcile(t, r, envtestNS, g.Name) // write
	require.Equal(t, 1, fb.writes)
	require.Contains(t, fb.groups, groupKey("", "team-a"))
	require.Equal(t, 5*time.Minute, res.RequeueAfter,
		"success path requeues at PeriodicInterval")

	got := getGroup(t, r, envtestNS, g.Name)
	require.NotEmpty(t, got.Status.GroupID, "BaoWrite mutator must stamp groupId on status")
	require.True(t, got.Status.BaoWritten,
		"B1: status.baoWritten must flip true after a successful BaoWrite")
	require.Equal(t, "team-a", got.Status.LastWrittenBaoName,
		"R1: status.lastWrittenBaoName must equal current BaoName() after create")
	require.Empty(t, got.Status.LastWrittenOpenBaoNamespace,
		"R1: status.lastWrittenOpenBaoNamespace must equal current OpenBaoNamespace() (root for this fixture)")
	cond := readyCond(t, got)
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
	require.Equal(t, resource.ReasonReconciled, cond.Reason)
}

// Drift path: bao state doesn't match spec.policies; reconcile must
// re-write and the bao-side payload converges.
func TestOpenBaoGroup_DriftPath_RewritesOnPolicyChange(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	g := sampleGroup("team-a")
	g.Spec.Policies = []string{"reader"}
	r := buildReconciler(t, fb, g)

	reconcile(t, r, envtestNS, g.Name)
	reconcile(t, r, envtestNS, g.Name)
	require.Equal(t, 1, fb.writes)

	// User edits policies. Simulate bao still holding the old set;
	// the next reconcile must observe drift and re-write.
	cur := getGroup(t, r, envtestNS, g.Name)
	cur.Spec.Policies = []string{"reader", "editor"}
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, envtestNS, g.Name)
	require.Equal(t, 2, fb.writes,
		"spec change must trigger a re-write")
	stored := fb.groups[groupKey("", "team-a")]
	require.ElementsMatch(t, []string{"reader", "editor"}, stored.Policies)
}

// OOB delete heals on next reconcile (D2 from acceptance battery).
func TestOpenBaoGroup_SelfHealOnOutOfBandDelete(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	g := sampleGroup("team-a")
	r := buildReconciler(t, fb, g)

	reconcile(t, r, envtestNS, g.Name)
	reconcile(t, r, envtestNS, g.Name)
	require.Equal(t, 1, fb.writes)

	delete(fb.groups, groupKey("", "team-a"))

	reconcile(t, r, envtestNS, g.Name)
	require.Equal(t, 2, fb.writes,
		"out-of-band delete must trigger a re-create on next reconcile")
	require.Contains(t, fb.groups, groupKey("", "team-a"))
}

// G1 from acceptance battery: a reconcile pass with no spec change
// must not mutate bao state.
func TestOpenBaoGroup_NoWriteStorm_OnReconcileWithoutSpecChange(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	g := sampleGroup("team-a")
	g.Spec.Policies = []string{"reader"}
	r := buildReconciler(t, fb, g)

	reconcile(t, r, envtestNS, g.Name)
	reconcile(t, r, envtestNS, g.Name)
	require.Equal(t, 1, fb.writes)

	// Multiple subsequent reconciles must observe no drift and skip BaoWrite.
	for i := 0; i < 3; i++ {
		reconcile(t, r, envtestNS, g.Name)
	}
	require.Equal(t, 1, fb.writes,
		"steady-state reconciles must not re-write a non-drifting group")
}

func TestOpenBaoGroup_DeletePath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	g := sampleGroup("doomed")
	r := buildReconciler(t, fb, g)

	reconcile(t, r, envtestNS, g.Name)
	reconcile(t, r, envtestNS, g.Name)
	require.Equal(t, 1, fb.writes)

	cur := getGroup(t, r, envtestNS, g.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, envtestNS, g.Name)

	require.Equal(t, 1, fb.deletes)
	require.NotContains(t, fb.groups, groupKey("", "doomed"))
	require.True(t, apierrors.IsNotFound(
		r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: g.Name}, &v1alpha1.OpenBaoGroup{})))
}

// status.baoWritten gates BaoDelete: a CR rejected at IsValid never wrote
// bao, so deletion must skip the BaoDelete call.
func TestOpenBaoGroup_DeleteSkipsBaoIfNeverWritten(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	g := sampleGroup("invalid")
	g.Spec.Type = "weird" // rejected by IsValid
	r := buildReconciler(t, fb, g)

	reconcile(t, r, envtestNS, g.Name)
	reconcile(t, r, envtestNS, g.Name)
	require.Equal(t, 0, fb.writes)

	cur := getGroup(t, r, envtestNS, g.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, envtestNS, g.Name)

	require.Equal(t, 0, fb.deletes,
		"BaoDelete must be skipped when status.baoWritten=false")
}

// Bao rejects a type change on an existing group. The controller must
// surface a clear ReasonInternalError instead of silently flapping.
func TestOpenBaoGroup_TypeImmutability_DetectedOnSpecChange(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	g := sampleGroup("team-a")
	r := buildReconciler(t, fb, g)

	reconcile(t, r, envtestNS, g.Name)
	reconcile(t, r, envtestNS, g.Name)
	require.Equal(t, 1, fb.writes)

	// Flip spec.type to external — bao would reject the rewrite.
	cur := getGroup(t, r, envtestNS, g.Name)
	cur.Spec.Type = v1alpha1.GroupTypeExternal
	require.NoError(t, r.Update(context.Background(), cur))

	res := reconcile(t, r, envtestNS, g.Name)
	require.Equal(t, 30*time.Second, res.RequeueAfter,
		"type-immutable error must requeue with ErrorBackoff")
	require.Equal(t, 1, fb.writes,
		"type-change attempt must NOT have written")
	cond := readyCond(t, getGroup(t, r, envtestNS, g.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonInternalError, cond.Reason)
	require.Contains(t, cond.Message, "immutable")
}

// 403 from bao surfaces as Ready=False / Reason=Forbidden.
func TestOpenBaoGroup_BaoForbidden(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.writeErr = &baoclient.StatusError{
		StatusCode: http.StatusForbidden,
		Inner:      errors.New("permission denied"),
	}
	g := sampleGroup("forbidden")
	r := buildReconciler(t, fb, g)

	reconcile(t, r, envtestNS, g.Name)
	res := reconcile(t, r, envtestNS, g.Name)

	require.Equal(t, 30*time.Second, res.RequeueAfter)
	cond := readyCond(t, getGroup(t, r, envtestNS, g.Name))
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonForbidden, cond.Reason)
}

// Invalid spec routes to ReasonInvalid (no requeue, no bao write).
func TestOpenBaoGroup_RejectsInvalidSpec(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	g := sampleGroup("ext-with-members")
	g.Spec.Type = v1alpha1.GroupTypeExternal
	g.Spec.MemberEntityIds = []string{"e-1"}
	r := buildReconciler(t, fb, g)

	reconcile(t, r, envtestNS, g.Name)
	res := reconcile(t, r, envtestNS, g.Name)

	require.Zero(t, res.RequeueAfter)
	require.Equal(t, 0, fb.writes)
	cond := readyCond(t, getGroup(t, r, envtestNS, g.Name))
	require.Equal(t, resource.ReasonInvalid, cond.Reason)
}

// C1: same name, different bao namespace → not a collision.
func TestOpenBaoGroup_NameCollision_DifferentBaoNamespaceIsNotACollision(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	a := sampleGroup("team-a")
	a.Namespace = nsA
	a.UID = uidA
	a.Spec.OpenBaoNamespace = "acme/"

	b := sampleGroup("team-a")
	b.Namespace = nsB
	b.UID = uidB
	b.Spec.OpenBaoNamespace = "globex/"

	r := buildReconciler(t, fb, a, b)
	reconcile(t, r, nsA, "team-a")
	reconcile(t, r, nsA, "team-a")
	reconcile(t, r, nsB, "team-a")
	reconcile(t, r, nsB, "team-a")

	require.Equal(t, 2, fb.writes,
		"same name in different bao namespaces must not collide")
}

// C2: same name + same bao namespace → older CR wins.
func TestOpenBaoGroup_NameCollision_OlderWins(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	older := sampleGroup("team-a")
	older.Namespace = nsA
	older.UID = uidA
	older.CreationTimestamp = metav1.NewTime(time.Now().Add(-1 * time.Hour))

	newer := sampleGroup("team-a")
	newer.Namespace = nsB
	newer.UID = uidB
	newer.CreationTimestamp = metav1.NewTime(time.Now())

	r := buildReconciler(t, fb, older, newer)

	// Reconcile newer first so its BaoWrite path triggers the
	// collision check before older has written.
	reconcile(t, r, nsB, "team-a")
	res := reconcile(t, r, nsB, "team-a")
	require.Equal(t, resource.PeriodicInterval, res.RequeueAfter)
	require.Equal(t, 0, fb.writes, "newer must not have written")

	cond := readyCond(t, getGroup(t, r, nsB, "team-a"))
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)
	require.Contains(t, cond.Message, "ns-a/team-a",
		"loser's message must name the older winner")

	// Older proceeds successfully.
	reconcile(t, r, nsA, "team-a")
	reconcile(t, r, nsA, "team-a")
	require.Equal(t, 1, fb.writes)
}

// C3c: when the winner is deleted, the loser becomes the new winner
// within PeriodicInterval and reaches Ready=True automatically.
func TestOpenBaoGroup_NameCollision_LoserHealsWhenWinnerDeleted(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	older := sampleGroup("team-a")
	older.Namespace = nsA
	older.UID = uidA
	older.CreationTimestamp = metav1.NewTime(time.Now().Add(-1 * time.Hour))

	newer := sampleGroup("team-a")
	newer.Namespace = nsB
	newer.UID = uidB
	newer.CreationTimestamp = metav1.NewTime(time.Now())

	r := buildReconciler(t, fb, older, newer)

	// Older wins, newer loses on first round.
	reconcile(t, r, nsA, "team-a")
	reconcile(t, r, nsA, "team-a")
	reconcile(t, r, nsB, "team-a")
	reconcile(t, r, nsB, "team-a")
	require.Equal(t, 1, fb.writes)
	cond := readyCond(t, getGroup(t, r, nsB, "team-a"))
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)

	// Delete the winner.
	winner := getGroup(t, r, nsA, "team-a")
	require.NoError(t, r.Delete(context.Background(), winner))
	reconcile(t, r, nsA, "team-a") // finalizer removes bao state + CR
	require.NotContains(t, fb.groups, groupKey("", "team-a"))

	// Next reconcile of the loser sees no other CR holds the
	// collision tuple → it writes successfully.
	reconcile(t, r, nsB, "team-a")
	require.Equal(t, 2, fb.writes,
		"loser must write once the winner is gone")

	cond = readyCond(t, getGroup(t, r, nsB, "team-a"))
	require.Equal(t, metav1.ConditionTrue, cond.Status)
	require.Equal(t, resource.ReasonReconciled, cond.Reason)
}

// E1: status.conditions[Ready].observedGeneration tracks
// metadata.generation after a successful reconcile.
//
// Cluster-verified end-to-end (a spec.policies edit bumps
// metadata.generation; the next reconcile lifts observedGeneration
// to match). The fake client doesn't always reproduce the apiserver's
// generation-bump-on-spec-update behaviour, so the unit test only
// asserts the steady-state equality on the canonical create path —
// the bump-then-follow case lives in the cluster battery.
func TestOpenBaoGroup_CreatePath_ObservedGenerationTracks(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	g := sampleGroup("team-a")
	g.Spec.Policies = []string{"reader"}
	r := buildReconciler(t, fb, g)

	reconcile(t, r, envtestNS, g.Name)
	reconcile(t, r, envtestNS, g.Name)

	got := getGroup(t, r, envtestNS, g.Name)
	cond := readyCond(t, got)
	require.NotNil(t, cond)
	require.Equal(t, got.Generation, cond.ObservedGeneration,
		"observedGeneration must equal metadata.generation after a successful reconcile")
}

// R1-R3: rename via spec.name cleans up the old bao identity.
func TestOpenBaoGroup_RenameTracking(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	g := sampleGroup("g1")
	r := buildReconciler(t, fb, g)

	reconcile(t, r, envtestNS, g.Name)
	reconcile(t, r, envtestNS, g.Name)
	require.Contains(t, fb.groups, groupKey("", "g1"))
	cur := getGroup(t, r, envtestNS, g.Name)
	require.Equal(t, "g1", cur.Status.LastWrittenBaoName)

	// Rename via spec.name.
	cur.Spec.Name = "g1-renamed"
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, envtestNS, g.Name)

	require.NotContains(t, fb.groups, groupKey("", "g1"),
		"old bao identity must be cleaned up after rename")
	require.Contains(t, fb.groups, groupKey("", "g1-renamed"))

	got := getGroup(t, r, envtestNS, g.Name)
	require.Equal(t, "g1-renamed", got.Status.LastWrittenBaoName,
		"LastWrittenBaoName must advance to the new identity after cleanup")
}

// Backfill recovers a lost groupId from a successful read.
func TestOpenBaoGroup_Backfill_RecoversGroupID(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	// Pre-populate bao with a group whose id we'll expect status to pick up.
	fb.groups[groupKey("", "team-a")] = &baoclient.IdentityGroup{
		ID:       "g-preexisting",
		Name:     "team-a",
		Type:     v1alpha1.GroupTypeInternal,
		Policies: []string{},
	}

	g := sampleGroup("team-a")
	r := buildReconciler(t, fb, g)

	reconcile(t, r, envtestNS, g.Name)
	reconcile(t, r, envtestNS, g.Name)

	got := getGroup(t, r, envtestNS, g.Name)
	require.Equal(t, "g-preexisting", got.Status.GroupID,
		"Backfill must stamp the bao-side id when status was empty")
	require.Equal(t, 0, fb.writes,
		"matching state must not trigger a write")
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
func (f *fakeBao) WriteJWTOIDCRole(ctx context.Context, mount, name string, spec baoclient.JWTOIDCRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadJWTOIDCRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.JWTOIDCRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteJWTOIDCRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return nil
}
