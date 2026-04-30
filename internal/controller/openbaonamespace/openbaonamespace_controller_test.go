package openbaonamespace

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

const envtestNS = "default"

const (
	uidA = "uid-a"
	uidB = "uid-b"
)

// ---- fake bao ----
//
// Models bao's namespace lifecycle in-memory keyed by (parentNs, name).
// All other Client methods are stubbed since the namespace controller
// touches none of them.
type fakeBao struct {
	// namespaces keyed as "<parentNs>|<name>".
	namespaces map[string]struct{}

	// Error injection.
	createErr error
	getErr    error
	deleteErr error

	// Call counters.
	creates, gets, deletes int
}

func newFakeBao() *fakeBao {
	return &fakeBao{namespaces: map[string]struct{}{}}
}

func nsKey(parent, name string) string { return parent + "|" + name }

// All non-namespace methods stubbed.
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

// Namespace lifecycle — the surface this fake exists for.

func (f *fakeBao) CreateNamespace(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	f.creates++
	if f.createErr != nil {
		return f.createErr
	}
	parent := baoclient.NamespaceFromOpts(opts)
	f.namespaces[nsKey(parent, name)] = struct{}{}
	return nil
}

func (f *fakeBao) GetNamespace(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.Namespace, error) {
	f.gets++
	if f.getErr != nil {
		return nil, f.getErr
	}
	parent := baoclient.NamespaceFromOpts(opts)
	if _, ok := f.namespaces[nsKey(parent, name)]; !ok {
		return nil, baoclient.ErrNotFound
	}
	return &baoclient.Namespace{Path: parent + name + "/"}, nil
}

func (f *fakeBao) DeleteNamespace(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	f.deletes++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	parent := baoclient.NamespaceFromOpts(opts)
	delete(f.namespaces, nsKey(parent, name))
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

// ---- helpers ----

func buildReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *OpenBaoNamespaceReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoNamespace{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoNamespace]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoNamespaceFinalizer,
		Handlers:      OpenBaoNamespaceHandlers(cl, fb),
	}
	return &OpenBaoNamespaceReconciler{VaultResource: base}
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

func sampleNamespace(name string) *v1alpha1.OpenBaoNamespace {
	n := &v1alpha1.OpenBaoNamespace{}
	n.Name = name
	n.Namespace = envtestNS
	return n
}

func reconcile(t *testing.T, r *OpenBaoNamespaceReconciler, ns, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getNS(t *testing.T, r *OpenBaoNamespaceReconciler, ns, name string) *v1alpha1.OpenBaoNamespace {
	t.Helper()
	var n v1alpha1.OpenBaoNamespace
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &n))
	return &n
}

func readyCond(t *testing.T, n *v1alpha1.OpenBaoNamespace) *metav1.Condition {
	t.Helper()
	for i := range n.Status.Conditions {
		if n.Status.Conditions[i].Type == resource.ConditionReady {
			return &n.Status.Conditions[i]
		}
	}
	return nil
}

// ---- create / drift / delete ----

func TestOpenBaoNamespace_CreatePath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	n := sampleNamespace("acme")
	r := buildReconciler(t, fb, n)

	reconcile(t, r, envtestNS, n.Name) // finalizer
	require.Contains(t, getNS(t, r, envtestNS, n.Name).Finalizers, OpenBaoNamespaceFinalizer)

	res := reconcile(t, r, envtestNS, n.Name) // write
	require.Equal(t, 1, fb.creates)
	require.Contains(t, fb.namespaces, nsKey("", "acme"))

	// Success path returns the periodic 5m resync — built-in self-heal.
	require.Equal(t, 5*time.Minute, res.RequeueAfter,
		"success path must requeue at PeriodicInterval for self-heal")

	cond := readyCond(t, getNS(t, r, envtestNS, n.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
	require.Equal(t, resource.ReasonReconciled, cond.Reason)
}

// Nested namespace: spec.openbaoNamespace="acme/" + spec.name=sub goes
// to CreateNamespace("sub", WithNamespace("acme/")) — bao writes to
// sys/namespaces/sub under the acme parent.
func TestOpenBaoNamespace_CreatePath_Nested(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	n := sampleNamespace("sub")
	n.Spec.OpenBaoNamespace = "acme/"
	r := buildReconciler(t, fb, n)

	reconcile(t, r, envtestNS, n.Name)
	reconcile(t, r, envtestNS, n.Name)

	require.Equal(t, 1, fb.creates)
	require.Contains(t, fb.namespaces, nsKey("acme/", "sub"),
		"nested create must address sub via WithNamespace(acme/), not flat sys/namespaces/acme/sub")
	require.NotContains(t, fb.namespaces, nsKey("", "sub"))
}

// Out-of-band deletion of the bao namespace heals on the next reconcile.
func TestOpenBaoNamespace_SelfHealOnOutOfBandDelete(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	n := sampleNamespace("acme")
	r := buildReconciler(t, fb, n)

	reconcile(t, r, envtestNS, n.Name)
	reconcile(t, r, envtestNS, n.Name)
	require.Equal(t, 1, fb.creates)

	// Simulate an out-of-band delete (someone curls bao directly).
	delete(fb.namespaces, nsKey("", "acme"))

	// Without a CR-spec change the controller is event-driven only;
	// the periodic resync is configured at the manager level so this
	// test simulates the periodic call by re-running Reconcile.
	reconcile(t, r, envtestNS, n.Name)
	require.Equal(t, 2, fb.creates,
		"periodic resync must re-create a bao namespace deleted out-of-band")
	require.Contains(t, fb.namespaces, nsKey("", "acme"))
}

func TestOpenBaoNamespace_DeletePath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	n := sampleNamespace("to-delete")
	r := buildReconciler(t, fb, n)

	reconcile(t, r, envtestNS, n.Name)
	reconcile(t, r, envtestNS, n.Name)
	require.Equal(t, 1, fb.creates)

	cur := getNS(t, r, envtestNS, n.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, envtestNS, n.Name)

	require.Equal(t, 1, fb.deletes)
	require.NotContains(t, fb.namespaces, nsKey("", "to-delete"))

	err := r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: n.Name}, &v1alpha1.OpenBaoNamespace{})
	require.True(t, apierrors.IsNotFound(err))
}

// Bao rejects DELETE on a namespace with live children (mounts, auth,
// child namespaces). The wrapper surfaces the 400 as *StatusError; the
// shared base keeps the finalizer in place when BaoDelete returns
// non-nil — the CR stays in Terminating until the children are
// removed and the next reconcile retries successfully.
func TestOpenBaoNamespace_DeleteBlockedByChildren_KeepsFinalizer(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.deleteErr = &baoclient.StatusError{
		StatusCode: http.StatusBadRequest,
		Inner:      errors.New(`{"errors":["namespace contains nested namespaces"]}`),
	}
	n := sampleNamespace("has-children")
	r := buildReconciler(t, fb, n)

	reconcile(t, r, envtestNS, n.Name)
	reconcile(t, r, envtestNS, n.Name)
	require.Equal(t, 1, fb.creates)

	cur := getNS(t, r, envtestNS, n.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	res := reconcile(t, r, envtestNS, n.Name)

	require.Equal(t, 30*time.Second, res.RequeueAfter,
		"blocked delete must retry with error backoff")
	require.Contains(t, getNS(t, r, envtestNS, n.Name).Finalizers, OpenBaoNamespaceFinalizer,
		"finalizer must stay in place while children block the delete")

	cond := readyCond(t, getNS(t, r, envtestNS, n.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Contains(t, cond.Message, "nested namespaces",
		"the bao error message must surface in the user-visible status")
}

// Once children are gone, the next reconcile completes the delete and
// removes the finalizer.
func TestOpenBaoNamespace_DeleteUnblocksAfterChildrenGone(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.deleteErr = &baoclient.StatusError{
		StatusCode: http.StatusBadRequest,
		Inner:      errors.New("namespace contains mounts"),
	}
	n := sampleNamespace("eventually-empty")
	r := buildReconciler(t, fb, n)

	reconcile(t, r, envtestNS, n.Name)
	reconcile(t, r, envtestNS, n.Name)

	cur := getNS(t, r, envtestNS, n.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, envtestNS, n.Name)

	cond := readyCond(t, getNS(t, r, envtestNS, n.Name))
	require.Equal(t, metav1.ConditionFalse, cond.Status)

	// User cleans up children.
	fb.deleteErr = nil

	reconcile(t, r, envtestNS, n.Name)
	require.True(t, apierrors.IsNotFound(
		r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: n.Name}, &v1alpha1.OpenBaoNamespace{})),
		"once children are gone the next reconcile should complete the delete")
}

func TestOpenBaoNamespace_BaoForbidden(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.createErr = &baoclient.StatusError{
		StatusCode: http.StatusForbidden,
		Inner:      errors.New("permission denied"),
	}
	n := sampleNamespace("forbidden")
	r := buildReconciler(t, fb, n)

	reconcile(t, r, envtestNS, n.Name)
	res := reconcile(t, r, envtestNS, n.Name)

	require.Equal(t, 30*time.Second, res.RequeueAfter)
	cond := readyCond(t, getNS(t, r, envtestNS, n.Name))
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonForbidden, cond.Reason)
}

// IsValid catches reserved-name + slash-in-name cases. The base routes
// to ReasonInvalid (no requeue, no bao write).
func TestOpenBaoNamespace_RejectsReservedName(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	n := sampleNamespace("sys") // bao-reserved
	r := buildReconciler(t, fb, n)

	reconcile(t, r, envtestNS, n.Name)
	res := reconcile(t, r, envtestNS, n.Name)

	require.Zero(t, res.RequeueAfter,
		"Invalid spec must not requeue — user has to fix the name")
	require.Equal(t, 0, fb.creates, "no bao write for invalid spec")
	cond := readyCond(t, getNS(t, r, envtestNS, n.Name))
	require.Equal(t, resource.ReasonInvalid, cond.Reason)
}

// Two CRs targeting the same (parent, name) tuple collide on first
// write. Order the reconciles so the newer CR attempts a write before
// the older has run — that's when the collision check actually fires
// (once the older has written, the newer's BaoGet finds the bao state
// already matches and skips BaoWrite, so no collision check runs).
// In steady state both CRs observe the same bao namespace; the
// "ownership" notion is fluid for namespaces because the spec is
// purely the (parent, name) tuple with no per-CR mutable bao state.
func TestOpenBaoNamespace_NameCollision_OlderWinsOnFirstWrite(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	older := sampleNamespace("acme")
	older.Namespace = "ns-a"
	older.UID = uidA
	older.CreationTimestamp = metav1.NewTime(time.Now().Add(-1 * time.Hour))

	newer := sampleNamespace("acme")
	newer.Namespace = "ns-b"
	newer.UID = uidB
	newer.CreationTimestamp = metav1.NewTime(time.Now())

	r := buildReconciler(t, fb, older, newer)

	// Reconcile newer first so its BaoWrite path runs before older has
	// created the bao namespace. The collision check finds older, applies
	// the older-wins tie-break, and refuses the write.
	reconcile(t, r, "ns-b", "acme") // finalizer
	res := reconcile(t, r, "ns-b", "acme")
	require.Equal(t, resource.PeriodicInterval, res.RequeueAfter,
		"collision is a stable state — loser should requeue at PeriodicInterval, not ErrorBackoff")
	require.Equal(t, 0, fb.creates, "newer must not have written")

	cond := readyCond(t, getNS(t, r, "ns-b", "acme"))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)
	require.Contains(t, cond.Message, "ns-a/acme",
		"loser's message should name the older winner")

	// Older reconciles successfully; newer's subsequent reconciles
	// observe the bao state and report Ready=True without retrying
	// the collision check (because no BaoWrite is needed). This is
	// intentional — namespaces have no per-CR mutable state, so once
	// the bao namespace exists, both CRs are "satisfied".
	reconcile(t, r, "ns-a", "acme")
	reconcile(t, r, "ns-a", "acme")
	require.Equal(t, 1, fb.creates)
}

// Same name in different parent contexts is not a collision — bao
// stores them as distinct namespaces (acme/sub vs globex/sub).
func TestOpenBaoNamespace_NameCollision_DifferentParentDoesNotCollide(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	a := sampleNamespace("sub")
	a.Namespace = "ns-a"
	a.UID = uidA
	a.Spec.OpenBaoNamespace = "acme/"

	b := sampleNamespace("sub")
	b.Namespace = "ns-b"
	b.UID = uidB
	b.Spec.OpenBaoNamespace = "globex/"

	r := buildReconciler(t, fb, a, b)

	reconcile(t, r, "ns-a", "sub")
	reconcile(t, r, "ns-a", "sub")
	reconcile(t, r, "ns-b", "sub")
	reconcile(t, r, "ns-b", "sub")

	require.Equal(t, 2, fb.creates)
	require.Contains(t, fb.namespaces, nsKey("acme/", "sub"))
	require.Contains(t, fb.namespaces, nsKey("globex/", "sub"))
}

// Regression for status.baoWritten gate: a CR rejected at IsValid
// (e.g. reserved name) never wrote bao, so deletion must skip
// BaoDelete to avoid a wasted call.
func TestOpenBaoNamespace_DeleteSkipsBaoIfNeverWritten(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	n := sampleNamespace("sys") // reserved
	r := buildReconciler(t, fb, n)

	reconcile(t, r, envtestNS, n.Name)
	reconcile(t, r, envtestNS, n.Name)
	require.Equal(t, 0, fb.creates)

	cur := getNS(t, r, envtestNS, n.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, envtestNS, n.Name)

	require.Equal(t, 0, fb.deletes,
		"BaoDelete must be skipped when status.baoWritten=false")
	require.True(t, apierrors.IsNotFound(
		r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: n.Name}, &v1alpha1.OpenBaoNamespace{})))
}
