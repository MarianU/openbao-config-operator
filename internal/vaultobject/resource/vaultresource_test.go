package resource

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// stubCR is a minimal VaultCR used to drive the shared reconcile base
// directly, without depending on a real primitive type. Behavioral hooks
// (deletable, conditions) are field-driven so each test can target a
// specific branch. Conditions live under .status so the fake client's
// status subresource handling can patch them like real CRDs do.
type stubCR struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Status    stubStatus `json:"status,omitempty"`
	Deletable bool
}

type stubStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	BaoWritten bool               `json:"baoWritten,omitempty"`
}

func (s *stubCR) GetPath() string                                            { return "stub/" + s.Name }
func (s *stubCR) GetPayload() map[string]any                                 { return map[string]any{"name": s.Name} }
func (s *stubCR) IsEquivalentToDesiredState(map[string]any) bool             { return true }
func (s *stubCR) IsInitialized() bool                                        { return true }
func (s *stubCR) IsValid() (bool, error)                                     { return true, nil }
func (s *stubCR) IsDeletable() bool                                          { return s.Deletable }
func (s *stubCR) PrepareInternalValues(context.Context, client.Object) error { return nil }
func (s *stubCR) PrepareTLSConfig(context.Context, client.Object) error      { return nil }
func (s *stubCR) GetConditions() []metav1.Condition                          { return s.Status.Conditions }
func (s *stubCR) SetConditions(c []metav1.Condition)                         { s.Status.Conditions = c }
func (s *stubCR) IsBaoWritten() bool                                         { return s.Status.BaoWritten }
func (s *stubCR) MarkBaoWritten()                                            { s.Status.BaoWritten = true }

func (s *stubCR) DeepCopyObject() runtime.Object {
	if s == nil {
		return nil
	}
	out := *s
	out.Status.Conditions = append([]metav1.Condition(nil), s.Status.Conditions...)
	return &out
}

var stubGV = schema.GroupVersion{Group: "test.stakater.com", Version: "v1"}

func stubScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	s.AddKnownTypes(stubGV, &stubCR{})
	metav1.AddToGroupVersion(s, stubGV)
	return s
}

// recordingLogger captures Info-level log lines so tests can assert
// operationally-visible messages were emitted.
type recordingLogger struct {
	mu    sync.Mutex
	lines []string
}

func newRecordingLogger() (logr.Logger, *recordingLogger) {
	rec := &recordingLogger{}
	l := funcr.New(func(prefix, args string) {
		rec.mu.Lock()
		rec.lines = append(rec.lines, prefix+" "+args)
		rec.mu.Unlock()
	}, funcr.Options{Verbosity: 0}) // V(0)=Info; V(1) would not be captured
	return l, rec
}

func (r *recordingLogger) contains(substr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, line := range r.lines {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

// recordingHandlers tracks invocation of BaoDelete so tests can assert
// the deletion path branched the right way.
type recordingHandlers struct {
	deleteCalls int
	deleteErr   error
}

func (r *recordingHandlers) handlers() Handlers[*stubCR] {
	return Handlers[*stubCR]{
		NewInstance: func() *stubCR { return &stubCR{} },
		BaoGet:      func(context.Context, *stubCR) (map[string]any, error) { return nil, ErrBaoNotFound },
		BaoWrite:    func(context.Context, *stubCR) error { return nil },
		BaoDelete: func(context.Context, *stubCR) error {
			r.deleteCalls++
			return r.deleteErr
		},
	}
}

// TestHandleDelete_IsDeletableFalseSkipsBaoDelete verifies the
// IsDeletable=false branch: even though the CR has BaoWritten=true (so
// the second branch would call BaoDelete), BaoDelete must NOT run because
// the primitive opted out of bao-side cleanup. The finalizer must still
// be released so the CR doesn't strand in Terminating.
func TestHandleDelete_IsDeletableFalseSkipsBaoDelete(t *testing.T) {
	t.Parallel()
	scheme := stubScheme(t)

	now := metav1.Now()
	obj := &stubCR{
		TypeMeta: metav1.TypeMeta{Kind: "Stub", APIVersion: stubGV.String()},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "no-delete",
			Namespace:         "default",
			Finalizers:        []string{"stub.finalizer"},
			DeletionTimestamp: &now,
		},
		Status:    stubStatus{BaoWritten: true},
		Deletable: false,
	}

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(obj).
		WithStatusSubresource(&stubCR{}).
		Build()

	h := &recordingHandlers{}
	r := &VaultResource[*stubCR]{
		Client:        cl,
		Scheme:        scheme,
		Handlers:      h.handlers(),
		FinalizerName: "stub.finalizer",
	}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "no-delete"},
	})
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, res)

	require.Equal(t, 0, h.deleteCalls,
		"BaoDelete must not be called when IsDeletable=false (intentional bao-side orphan)")

	// Finalizer must be removed; with no other finalizers the fake client
	// reports the object as gone after Update.
	got := &stubCR{}
	err = cl.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "no-delete"}, got)
	if err == nil {
		require.False(t, controllerutil.ContainsFinalizer(got, "stub.finalizer"),
			"finalizer must be released so CR can be reaped")
	}
}

// TestHandleDelete_NotWrittenSkipsBaoDelete covers the common path where
// a CR was applied with bad spec, never wrote to bao, then was deleted.
// The durable status.baoWritten field is false, so BaoDelete must be
// skipped to avoid stranding the CR in Terminating on primitives with
// strict delete endpoints.
func TestHandleDelete_NotWrittenSkipsBaoDelete(t *testing.T) {
	t.Parallel()
	scheme := stubScheme(t)

	now := metav1.Now()
	obj := &stubCR{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "never-written",
			Namespace:         "default",
			Finalizers:        []string{"stub.finalizer"},
			DeletionTimestamp: &now,
		},
		Status:    stubStatus{BaoWritten: false}, // no successful write recorded
		Deletable: true,
	}

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(obj).
		WithStatusSubresource(&stubCR{}).
		Build()

	h := &recordingHandlers{}
	r := &VaultResource[*stubCR]{
		Client:        cl,
		Scheme:        scheme,
		Handlers:      h.handlers(),
		FinalizerName: "stub.finalizer",
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "never-written"},
	})
	require.NoError(t, err)
	require.Equal(t, 0, h.deleteCalls,
		"BaoDelete must be skipped when CR has BaoWritten=false")
}

// TestHandleDelete_WrittenThenReadyFlippedFalseStillDeletes covers the
// orphan-leak case the wasEverReady heuristic missed: a CR that wrote to
// bao successfully (BaoWritten=true), then later flipped Ready=True→False
// (token lost capability, drift check failure, etc.) and was then
// deleted by the user. The bao state exists; cleanup must run.
func TestHandleDelete_WrittenThenReadyFlippedFalseStillDeletes(t *testing.T) {
	t.Parallel()
	scheme := stubScheme(t)

	now := metav1.Now()
	obj := &stubCR{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "wrote-then-broke",
			Namespace:         "default",
			Finalizers:        []string{"stub.finalizer"},
			DeletionTimestamp: &now,
		},
		Status: stubStatus{
			BaoWritten: true, // successful write happened earlier
			Conditions: []metav1.Condition{{
				Type:   ConditionReady,
				Status: metav1.ConditionFalse, // but Ready flipped False since
				Reason: "Forbidden",
			}},
		},
		Deletable: true,
	}

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(obj).
		WithStatusSubresource(&stubCR{}).
		Build()

	h := &recordingHandlers{}
	r := &VaultResource[*stubCR]{
		Client:        cl,
		Scheme:        scheme,
		Handlers:      h.handlers(),
		FinalizerName: "stub.finalizer",
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "wrote-then-broke"},
	})
	require.NoError(t, err)
	require.Equal(t, 1, h.deleteCalls,
		"BaoDelete must run when BaoWritten=true even if Ready is currently False")
}

// TestReconcile_AddFinalizerUpdateFailureWritesStatus exercises the path
// where the metadata Update that adds the finalizer fails. The base must
// log the failure, write Ready=False so the user sees something in
// kubectl describe, and surface the error to controller-runtime so it
// requeues. Without this, a future refactor that drops the setReady call
// from the AddFinalizer error branch would silently leave the CR with a
// stale Ready while the controller hot-loops.
func TestReconcile_AddFinalizerUpdateFailureWritesStatus(t *testing.T) {
	t.Parallel()
	scheme := stubScheme(t)

	obj := &stubCR{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-finalizer-yet",
			Namespace: "default",
			// No finalizers yet — Reconcile takes the AddFinalizer branch.
		},
	}

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(obj).
		WithStatusSubresource(&stubCR{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.UpdateOption) error {
				// Reject the metadata Update that AddFinalizer triggers.
				return apierrors.NewServiceUnavailable("apiserver overloaded")
			},
		}).
		Build()

	r := &VaultResource[*stubCR]{
		Client:        cl,
		Scheme:        scheme,
		Handlers:      (&recordingHandlers{}).handlers(),
		FinalizerName: "stub.finalizer",
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "no-finalizer-yet"},
	})
	require.Error(t, err, "Update failure must propagate so controller-runtime requeues")

	got := &stubCR{}
	require.NoError(t, cl.Get(context.Background(),
		types.NamespacedName{Namespace: "default", Name: "no-finalizer-yet"}, got))
	require.Len(t, got.Status.Conditions, 1, "Ready must be written so the failure is user-visible")
	require.Equal(t, ConditionReady, got.Status.Conditions[0].Type)
	require.Equal(t, metav1.ConditionFalse, got.Status.Conditions[0].Status)
}

// TestSetReady_RetriesOnConflict covers the RetryOnConflict path inside
// setReady: a 409 from the apiserver must trigger a re-fetch + re-patch,
// and the second attempt must succeed against the latest object. Without
// this, a future refactor that drops MergeFrom(origObj) would silently
// stop preserving condition state under contention.
func TestSetReady_RetriesOnConflict(t *testing.T) {
	t.Parallel()
	scheme := stubScheme(t)

	obj := &stubCR{
		ObjectMeta: metav1.ObjectMeta{Name: "retry", Namespace: "default"},
	}

	var patchCalls int
	var mu sync.Mutex
	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(obj).
		WithStatusSubresource(&stubCR{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, sub string, o client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				mu.Lock()
				patchCalls++
				n := patchCalls
				mu.Unlock()
				if n == 1 {
					// First attempt: simulate a conflict from a concurrent writer.
					return apierrors.NewConflict(
						schema.GroupResource{Group: stubGV.Group, Resource: "stubcrs"},
						o.GetName(), nil)
				}
				return c.Status().Patch(ctx, o, patch, opts...)
			},
		}).
		Build()

	r := &VaultResource[*stubCR]{
		Client:        cl,
		Scheme:        scheme,
		Handlers:      (&recordingHandlers{}).handlers(),
		FinalizerName: "stub.finalizer",
	}

	err := r.setReady(context.Background(),
		types.NamespacedName{Namespace: "default", Name: "retry"},
		metav1.ConditionTrue, "Reconciled", "")
	require.NoError(t, err, "RetryOnConflict must recover from a 409")

	mu.Lock()
	require.GreaterOrEqual(t, patchCalls, 2, "expected at least one retry after the simulated conflict")
	mu.Unlock()

	// Confirm the condition actually landed on the latest object.
	got := &stubCR{}
	require.NoError(t, cl.Get(context.Background(),
		types.NamespacedName{Namespace: "default", Name: "retry"}, got))
	require.Len(t, got.Status.Conditions, 1)
	require.Equal(t, ConditionReady, got.Status.Conditions[0].Type)
	require.Equal(t, metav1.ConditionTrue, got.Status.Conditions[0].Status)
}

// Retained as a regression sentinel: the previous implementation logged
// "may be orphaned" from a transient-condition heuristic. After replacing
// it with status.baoWritten, the log line should NOT fire — the orphan
// scenario is now handled by actually running BaoDelete.
func TestHandleDelete_NoOrphanLogAfterStructuralFix(t *testing.T) {
	t.Parallel()
	scheme := stubScheme(t)

	now := metav1.Now()
	obj := &stubCR{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "no-orphan-log",
			Namespace:         "default",
			Finalizers:        []string{"stub.finalizer"},
			DeletionTimestamp: &now,
		},
		Status: stubStatus{
			BaoWritten: false,
			Conditions: []metav1.Condition{{
				Type:   ConditionReady,
				Status: metav1.ConditionFalse,
				Reason: "Forbidden",
			}},
		},
		Deletable: true,
	}

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(obj).
		WithStatusSubresource(&stubCR{}).
		Build()

	h := &recordingHandlers{}
	r := &VaultResource[*stubCR]{
		Client:        cl,
		Scheme:        scheme,
		Handlers:      h.handlers(),
		FinalizerName: "stub.finalizer",
	}

	logger, rec := newRecordingLogger()
	ctx := log.IntoContext(context.Background(), logger)

	_, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "no-orphan-log"},
	})
	require.NoError(t, err)
	require.Equal(t, 0, h.deleteCalls)
	require.False(t, rec.contains("may be orphaned"),
		"the transient orphan-candidate log was removed when status.baoWritten took over the cleanup decision; it must not return")
}
