package vco

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

	vcov1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/vco/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

// ---- fake bao ----

type fakeBao struct {
	policies map[string]string // name -> body

	// Error injection.
	upsertErr error
	getErr    error
	deleteErr error

	// Call counters.
	upserts, gets, deletes int
}

func newFakeBao() *fakeBao {
	return &fakeBao{policies: map[string]string{}}
}

func (f *fakeBao) CheckKVv2Mount(ctx context.Context, mount string) (bool, error) { return true, nil }
func (f *fakeBao) CheckAuthMount(ctx context.Context, mount string) (bool, error) { return true, nil }
func (f *fakeBao) EnableAuthMount(ctx context.Context, mount, typ string) error   { return nil }

func (f *fakeBao) UpsertPolicy(ctx context.Context, name, rules string) error {
	f.upserts++
	if f.upsertErr != nil {
		return f.upsertErr
	}
	f.policies[name] = rules
	return nil
}
func (f *fakeBao) GetPolicy(ctx context.Context, name string) (string, error) {
	f.gets++
	if f.getErr != nil {
		return "", f.getErr
	}
	body, ok := f.policies[name]
	if !ok {
		return "", baoclient.ErrNotFound
	}
	return body, nil
}
func (f *fakeBao) DeletePolicy(ctx context.Context, name string) error {
	f.deletes++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.policies, name)
	return nil
}
func (f *fakeBao) UpsertK8sRole(ctx context.Context, _, _ string, _ baoclient.K8sRoleSpec) error {
	return nil
}
func (f *fakeBao) GetK8sRole(ctx context.Context, _, _ string) (*baoclient.K8sRole, error) {
	return nil, baoclient.ErrNotFound
}

// ---- helpers ----

func buildReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *PolicyReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, vcov1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&vcov1alpha1.Policy{}).
		Build()

	base := &resource.VaultResource[*vcov1alpha1.Policy]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: PolicyFinalizer,
		Handlers:      PolicyHandlers(cl, fb), // production handlers — exercises collision check
	}
	return &PolicyReconciler{VaultResource: base}
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

func samplePolicy(name string) *vcov1alpha1.Policy {
	p := &vcov1alpha1.Policy{}
	p.Name = name
	p.Namespace = "default"
	p.Spec.Policy = `path "secret/*" { capabilities = ["read"] }`
	return p
}

func samplePolicyIn(ns, name string) *vcov1alpha1.Policy {
	p := samplePolicy(name)
	p.Namespace = ns
	return p
}

func reconcileNS(t *testing.T, r *PolicyReconciler, ns, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getPolicyNS(t *testing.T, r *PolicyReconciler, ns, name string) *vcov1alpha1.Policy {
	t.Helper()
	var p vcov1alpha1.Policy
	err := r.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &p)
	require.NoError(t, err)
	return &p
}

func reconcile(t *testing.T, r *PolicyReconciler, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: name},
	})
	require.NoError(t, err)
	return res
}

func getPolicy(t *testing.T, r *PolicyReconciler, name string) *vcov1alpha1.Policy {
	t.Helper()
	var p vcov1alpha1.Policy
	err := r.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: name}, &p)
	require.NoError(t, err)
	return &p
}

func readyCond(t *testing.T, p *vcov1alpha1.Policy) *metav1.Condition {
	t.Helper()
	for i := range p.Status.Conditions {
		if p.Status.Conditions[i].Type == resource.ConditionReady {
			return &p.Status.Conditions[i]
		}
	}
	return nil
}

// ---- tests ----

func TestPolicy_CreatePath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	p := samplePolicy("secret-reader")
	r := buildReconciler(t, fb, p)

	// First reconcile adds the finalizer.
	reconcile(t, r, p.Name)
	got := getPolicy(t, r, p.Name)
	require.Contains(t, got.Finalizers, PolicyFinalizer, "finalizer should be added")

	// Second reconcile performs the write.
	reconcile(t, r, p.Name)
	require.Equal(t, 1, fb.upserts, "bao policy should be upserted once")
	require.Equal(t, p.Spec.Policy, fb.policies[p.Name])

	cond := readyCond(t, getPolicy(t, r, p.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
	require.Equal(t, resource.ReasonReconciled, cond.Reason)
}

func TestPolicy_EditPath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	p := samplePolicy("editable")
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name) // finalizer
	reconcile(t, r, p.Name) // initial write
	require.Equal(t, 1, fb.upserts)

	// Edit the CR spec.
	cur := getPolicy(t, r, p.Name)
	cur.Spec.Policy = `path "secret/*" { capabilities = ["read", "list"] }`
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, p.Name)
	require.Equal(t, 2, fb.upserts, "edit should trigger a second upsert")
	require.Equal(t, cur.Spec.Policy, fb.policies[p.Name])
}

func TestPolicy_DriftCorrection(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	p := samplePolicy("drifter")
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name) // finalizer
	reconcile(t, r, p.Name) // initial write
	require.Equal(t, 1, fb.upserts)

	// Someone mutates the bao-side body out-of-band.
	fb.policies[p.Name] = "drifted body"

	reconcile(t, r, p.Name)
	require.Equal(t, 2, fb.upserts, "drift should trigger re-upsert")
	require.Equal(t, p.Spec.Policy, fb.policies[p.Name])
}

func TestPolicy_DeletePath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	p := samplePolicy("to-delete")
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name) // finalizer
	reconcile(t, r, p.Name) // initial write
	require.Equal(t, 1, fb.upserts)

	// Mark the CR for deletion via the client API; the fake client respects
	// finalizers and will keep the object present until the finalizer is
	// removed by the reconciler.
	cur := getPolicy(t, r, p.Name)
	require.NoError(t, r.Delete(context.Background(), cur))

	reconcile(t, r, p.Name)
	require.Equal(t, 1, fb.deletes, "delete should have been called once")
	_, stillThere := fb.policies[p.Name]
	require.False(t, stillThere, "bao-side policy should be gone")

	// After finalizer removal the CR is gone.
	err := r.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: p.Name}, &vcov1alpha1.Policy{})
	require.True(t, apierrors.IsNotFound(err), "CR should be deleted after finalizer removal")
}

func TestPolicy_BaoForbidden(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	// The wrapper at internal/client tags every SDK error with HTTP status
	// via *StatusError. Tests inject the same shape so classification goes
	// through the structured path, not the message body.
	fb.upsertErr = &baoclient.StatusError{
		StatusCode: http.StatusForbidden,
		Inner:      errors.New("permission denied"),
	}
	p := samplePolicy("forbidden-p")
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name) // finalizer
	res := reconcile(t, r, p.Name)

	require.Equal(t, 30*time.Second, res.RequeueAfter, "should requeue with error backoff")
	cond := readyCond(t, getPolicy(t, r, p.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonForbidden, cond.Reason)
}

func TestPolicy_BaoUnreachable(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	// Network-layer errors don't carry an HTTP status; the wrapper passes
	// them through unwrapped, classifier returns ReasonBaoError.
	fb.getErr = errors.New("dial tcp 127.0.0.1:8200: connection refused")
	p := samplePolicy("unreachable-p")
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name) // finalizer
	res := reconcile(t, r, p.Name)

	require.Equal(t, 30*time.Second, res.RequeueAfter)
	cond := readyCond(t, getPolicy(t, r, p.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonBaoError, cond.Reason)
}

// Accessor-placeholder rejection is a spec-level invalid (lives in IsValid),
// not a runtime error. The base must NOT requeue; the user has to fix the
// spec to recover. Asserts: Ready=False/Reason=Invalid, no requeue, no bao
// write.
func TestPolicy_AccessorTemplating_RejectedAsInvalidNoRequeue(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	p := samplePolicy("templater")
	p.Spec.Policy = `path "x" { allowed_parameters = { "accessor" = ["${auth/kubernetes/@accessor}"] } }`
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name) // finalizer
	res := reconcile(t, r, p.Name)

	require.Zero(t, res.RequeueAfter, "Invalid spec should not requeue (user must fix spec)")
	require.False(t, res.Requeue)
	require.Equal(t, 0, fb.upserts, "no bao write should happen when spec is invalid")
	cond := readyCond(t, getPolicy(t, r, p.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonInvalid, cond.Reason)
}

func TestPolicy_Idempotent_NoChangeNoRewrite(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	p := samplePolicy("stable")
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name) // finalizer
	reconcile(t, r, p.Name) // write
	require.Equal(t, 1, fb.upserts)

	// Reconcile again without any change — should NOT rewrite.
	reconcile(t, r, p.Name)
	require.Equal(t, 1, fb.upserts, "equivalent state should not trigger a rewrite")
}

// Bao policy names are global; our CRD is namespaced. Two CRs in different
// k8s namespaces with the same metadata.name (or spec.name) would otherwise
// silently overwrite each other on every reconcile. The Policy controller
// guards this via checkPolicyNameCollision: older-CreationTimestamp wins;
// the loser surfaces Ready=False, Reason=NameCollision and refuses to write.
func TestPolicy_NameCollision_OlderWinsLoserRefusesWrite(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	older := samplePolicyIn("ns-a", "editor")
	older.UID = "uid-older"
	older.CreationTimestamp = metav1.NewTime(time.Now().Add(-1 * time.Hour))

	newer := samplePolicyIn("ns-b", "editor") // same metadata.name → same BaoName
	newer.UID = "uid-newer"
	newer.CreationTimestamp = metav1.NewTime(time.Now())
	newer.Spec.Policy = `path "secret/somethingelse/*" { capabilities = ["read"] }`

	r := buildReconciler(t, fb, older, newer)

	// Older reconciles first: finalizer + write. No collision.
	reconcileNS(t, r, "ns-a", "editor")
	reconcileNS(t, r, "ns-a", "editor")
	require.Equal(t, 1, fb.upserts, "older CR should successfully write")
	require.Equal(t, older.Spec.Policy, fb.policies["editor"])

	cond := readyCond(t, getPolicyNS(t, r, "ns-a", "editor"))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status, "older CR should be Ready=True")

	// Newer reconciles: finalizer added, then BaoWrite refuses with collision.
	reconcileNS(t, r, "ns-b", "editor") // finalizer
	res := reconcileNS(t, r, "ns-b", "editor")

	require.Equal(t, 30*time.Second, res.RequeueAfter, "collision should retry with backoff")
	require.Equal(t, 1, fb.upserts, "newer CR must NOT have written — older still owns the bao name")
	require.Equal(t, older.Spec.Policy, fb.policies["editor"], "older's body must not be overwritten")

	loser := getPolicyNS(t, r, "ns-b", "editor")
	cond = readyCond(t, loser)
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status, "newer (loser) should be Ready=False")
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)
	require.Contains(t, cond.Message, "ns-a/editor", "message should name the winning CR")
}

func TestPolicy_NameCollision_TimestampTieBrokenLexicographically(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	now := metav1.NewTime(time.Now())

	// Both created at the same instant → namespace/name lex order wins.
	// "ns-a/editor" < "ns-b/editor" → ns-a wins.
	a := samplePolicyIn("ns-a", "editor")
	a.UID = "uid-a"
	a.CreationTimestamp = now

	b := samplePolicyIn("ns-b", "editor")
	b.UID = "uid-b"
	b.CreationTimestamp = now
	b.Spec.Policy = `path "different/*" { capabilities = ["list"] }`

	r := buildReconciler(t, fb, a, b)

	reconcileNS(t, r, "ns-a", "editor")
	reconcileNS(t, r, "ns-a", "editor")
	require.Equal(t, 1, fb.upserts, "ns-a (lex earlier) should write")

	reconcileNS(t, r, "ns-b", "editor")
	reconcileNS(t, r, "ns-b", "editor")

	require.Equal(t, 1, fb.upserts, "ns-b (lex later) must NOT write")
	condB := readyCond(t, getPolicyNS(t, r, "ns-b", "editor"))
	require.NotNil(t, condB)
	require.Equal(t, resource.ReasonNameCollision, condB.Reason)
}

func TestPolicy_NameCollision_DistinctSpecNamesDoNotCollide(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	// Same metadata.name but distinct spec.name → distinct BaoName → no collision.
	a := samplePolicyIn("ns-a", "shared")
	a.UID = "uid-a"
	a.Spec.Name = "ns-a-shared"

	b := samplePolicyIn("ns-b", "shared")
	b.UID = "uid-b"
	b.Spec.Name = "ns-b-shared"

	r := buildReconciler(t, fb, a, b)

	reconcileNS(t, r, "ns-a", "shared") // finalizer
	reconcileNS(t, r, "ns-a", "shared") // write
	reconcileNS(t, r, "ns-b", "shared") // finalizer
	reconcileNS(t, r, "ns-b", "shared") // write

	require.Equal(t, 2, fb.upserts, "distinct bao names → both writes succeed")
	require.Contains(t, fb.policies, "ns-a-shared")
	require.Contains(t, fb.policies, "ns-b-shared")
}

// Regression for the wasEverReady guard: a CR that never reached Ready=True
// (e.g. spec.policy contained an accessor placeholder → IsValid rejected)
// must delete cleanly without ever calling BaoDelete. Otherwise primitives
// with strict delete endpoints would strand CRs in Terminating.
func TestPolicy_DeleteSkipsBaoIfNeverReady(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	p := samplePolicy("never-ready")
	p.Spec.Policy = `path "x" { allowed_parameters = { "accessor" = ["${auth/kubernetes/@accessor}"] } }`
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name) // finalizer
	reconcile(t, r, p.Name) // IsValid rejects → Ready=False, no write
	require.Equal(t, 0, fb.upserts)

	// Confirm Ready was never True.
	cond := readyCond(t, getPolicy(t, r, p.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonInvalid, cond.Reason)

	// Delete the CR.
	cur := getPolicy(t, r, p.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, p.Name)

	// BaoDelete must NOT have fired.
	require.Equal(t, 0, fb.deletes, "BaoDelete should be skipped for CRs that never reached Ready=True")

	// CR is gone (finalizer was released).
	err := r.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: p.Name}, &vcov1alpha1.Policy{})
	require.True(t, apierrors.IsNotFound(err))
}
