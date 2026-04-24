package vco

import (
	"context"
	"errors"
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
		return "", errors.New("policy not found 404")
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
	return nil, nil
}
func (f *fakeBao) ReadPath(ctx context.Context, _ string) (map[string]any, error) { return nil, nil }

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
		Handlers: resource.Handlers[*vcov1alpha1.Policy]{
			NewInstance: func() *vcov1alpha1.Policy { return &vcov1alpha1.Policy{} },
			BaoGet: func(ctx context.Context, p *vcov1alpha1.Policy) (map[string]any, error) {
				body, err := fb.GetPolicy(ctx, p.BaoName())
				if err != nil {
					msg := err.Error()
					if containsAny(msg, "404", "not found") {
						return nil, resource.ErrBaoNotFound
					}
					return nil, err
				}
				if body == "" {
					return nil, resource.ErrBaoNotFound
				}
				return map[string]any{"policy": body}, nil
			},
			BaoWrite: func(ctx context.Context, p *vcov1alpha1.Policy) error {
				return fb.UpsertPolicy(ctx, p.BaoName(), p.Spec.Policy)
			},
			BaoDelete: func(ctx context.Context, p *vcov1alpha1.Policy) error {
				return fb.DeletePolicy(ctx, p.BaoName())
			},
		},
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

func containsAny(s string, subs ...string) bool {
	low := ""
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			low += string(c + 32)
		} else {
			low += string(c)
		}
	}
	for _, sub := range subs {
		if contains(low, sub) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func samplePolicy(name string) *vcov1alpha1.Policy {
	p := &vcov1alpha1.Policy{}
	p.Name = name
	p.Namespace = "default"
	p.Spec.Policy = `path "secret/*" { capabilities = ["read"] }`
	p.Spec.Type = "acl"
	return p
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
	fb.upsertErr = errors.New("bao PUT /v1/sys/policies/acl/p: permission denied")
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

func TestPolicy_PrepareInternalValues_AccessorTemplatingRejected(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	p := samplePolicy("templater")
	p.Spec.Policy = `path "x" { allowed_parameters = { "accessor" = ["${auth/kubernetes/@accessor}"] } }`
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name) // finalizer
	res := reconcile(t, r, p.Name)

	require.Equal(t, 30*time.Second, res.RequeueAfter)
	require.Equal(t, 0, fb.upserts, "no bao write should happen when templating is rejected")
	cond := readyCond(t, getPolicy(t, r, p.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
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
