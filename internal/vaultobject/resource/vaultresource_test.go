package resource

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
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
	// OBNamespace backs OpenBaoNamespace(). Empty means bao's root namespace,
	// which the identity suffix renders differently from a named one.
	OBNamespace string
}

type stubStatus struct {
	Conditions                  []metav1.Condition `json:"conditions,omitempty"`
	BaoWritten                  bool               `json:"baoWritten,omitempty"`
	LastWrittenBaoName          string             `json:"lastWrittenBaoName,omitempty"`
	LastWrittenOpenBaoNamespace string             `json:"lastWrittenOpenBaoNamespace,omitempty"`
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
func (s *stubCR) BaoName() string                                            { return s.Name }
func (s *stubCR) OpenBaoNamespace() string                                   { return s.OBNamespace }
func (s *stubCR) LastWrittenBaoName() string                                 { return s.Status.LastWrittenBaoName }
func (s *stubCR) LastWrittenOpenBaoNamespace() string                        { return s.Status.LastWrittenOpenBaoNamespace }
func (s *stubCR) SetLastWrittenBaoIdentity(name, namespace string) {
	s.Status.LastWrittenBaoName = name
	s.Status.LastWrittenOpenBaoNamespace = namespace
}

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
		BaoWrite:    func(context.Context, *stubCR) (StatusMutator[*stubCR], error) { return nil, nil },
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
	rec := record.NewFakeRecorder(16)
	r := &VaultResource[*stubCR]{
		Client:        cl,
		Scheme:        scheme,
		Handlers:      h.handlers(),
		FinalizerName: "stub.finalizer",
		Recorder:      rec,
	}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "no-delete"},
	})
	require.NoError(t, err)
	require.Equal(t, ctrl.Result{}, res)

	// The CR is about to disappear; the Event is the only k8s-side trace
	// of what was left behind in bao.
	events := drainEvents(rec)
	require.Len(t, events, 1)
	require.Contains(t, events[0], "BaoObjectOrphaned")

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
	rec := record.NewFakeRecorder(16)
	r := &VaultResource[*stubCR]{
		Client:        cl,
		Scheme:        scheme,
		Handlers:      h.handlers(),
		FinalizerName: "stub.finalizer",
		Recorder:      rec,
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "never-written"},
	})
	require.NoError(t, err)
	require.Equal(t, 0, h.deleteCalls,
		"BaoDelete must be skipped when CR has BaoWritten=false")
	require.Empty(t, drainEvents(rec))
}

// A never-written, non-deletable CR finalizes with no orphan Event or
// log — nothing exists in bao to orphan. Pins the handleDelete case
// ordering (!IsBaoWritten before !IsDeletable).
func TestHandleDelete_NeverWrittenNonDeletable_NoFalseOrphanSignal(t *testing.T) {
	t.Parallel()
	scheme := stubScheme(t)

	now := metav1.Now()
	obj := &stubCR{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "never-written-no-delete",
			Namespace:         "default",
			Finalizers:        []string{"stub.finalizer"},
			DeletionTimestamp: &now,
		},
		Status:    stubStatus{BaoWritten: false},
		Deletable: false,
	}

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(obj).
		WithStatusSubresource(&stubCR{}).
		Build()

	h := &recordingHandlers{}
	rec := record.NewFakeRecorder(16)
	r := &VaultResource[*stubCR]{
		Client:        cl,
		Scheme:        scheme,
		Handlers:      h.handlers(),
		FinalizerName: "stub.finalizer",
		Recorder:      rec,
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "never-written-no-delete"},
	})
	require.NoError(t, err)
	require.Equal(t, 0, h.deleteCalls)
	require.Empty(t, drainEvents(rec),
		"nothing was written, so nothing was orphaned — no Event")

	got := &stubCR{}
	err = cl.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "never-written-no-delete"}, got)
	if err == nil {
		require.False(t, controllerutil.ContainsFinalizer(got, "stub.finalizer"))
	}
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
// kubeClientPeekingStub is a stub primitive whose PrepareInternalValues
// captures whatever it sees in the reconcile ctx under the upstream-VCO
// "kubeClient" key. Captures are written to package-level variables
// rather than fields on the stub itself: the shared base's status-patch
// path also uses NewInstance + Get to materialize the CR for the patch,
// and Get from the fake client overwrites un-tagged fields, so per-
// instance fields would be reset before the test reads them.
type kubeClientPeekingStub struct {
	stubCR
}

var (
	peekedKubeClient client.Client
	peekedOK         bool
)

func (k *kubeClientPeekingStub) PrepareInternalValues(ctx context.Context, _ client.Object) error {
	//nolint:staticcheck // upstream-VCO key contract
	peekedKubeClient, peekedOK = ctx.Value("kubeClient").(client.Client)
	return nil
}

func (k *kubeClientPeekingStub) DeepCopyObject() runtime.Object {
	if k == nil {
		return nil
	}
	out := *k
	out.Status.Conditions = append([]metav1.Condition(nil), k.Status.Conditions...)
	return &out
}

// TestVaultResource_PrepareInternalValuesReceivesKubeClient guards the
// invariant that the base injects r.Client into the reconcile ctx under
// the "kubeClient" key before calling PrepareInternalValues. Primitives
// that resolve k8s state during preparation (label-selector lookups,
// secret-ref dereferencing) read it back from ctx; a refactor that set
// the value on a different ctx variable would silently drop it and
// every such primitive would fail its lookups at runtime.
func TestVaultResource_PrepareInternalValuesReceivesKubeClient(t *testing.T) {
	// Captures live on package-level variables; can't run in parallel
	// with another test using the same stub. No other test does today.
	peekedKubeClient = nil
	peekedOK = false

	scheme := runtime.NewScheme()
	scheme.AddKnownTypes(stubGV, &kubeClientPeekingStub{})
	metav1.AddToGroupVersion(scheme, stubGV)

	stub := &kubeClientPeekingStub{
		stubCR: stubCR{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "peek",
				Namespace:  "default",
				Finalizers: []string{"stub.finalizer"},
			},
		},
	}

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(stub).
		WithStatusSubresource(&kubeClientPeekingStub{}).
		Build()

	r := &VaultResource[*kubeClientPeekingStub]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: "stub.finalizer",
		Handlers: Handlers[*kubeClientPeekingStub]{
			NewInstance: func() *kubeClientPeekingStub { return &kubeClientPeekingStub{} },
			BaoGet: func(context.Context, *kubeClientPeekingStub) (map[string]any, error) {
				return nil, ErrBaoNotFound
			},
			BaoWrite: func(context.Context, *kubeClientPeekingStub) (StatusMutator[*kubeClientPeekingStub], error) {
				return nil, nil
			},
			BaoDelete: func(context.Context, *kubeClientPeekingStub) error { return nil },
		},
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "peek"},
	})
	require.NoError(t, err)

	require.True(t, peekedOK, `ctx.Value("kubeClient") must yield a client.Client`)
	require.NotNil(t, peekedKubeClient, "captured kube client must not be nil")
	require.Same(t, cl, peekedKubeClient,
		"the injected kube client must be the same client the base was constructed with")
}

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

// readyCond returns the Ready condition from a freshly-fetched stubCR.
func readyCond(t *testing.T, cl client.Client, name string) *metav1.Condition {
	t.Helper()
	got := &stubCR{}
	require.NoError(t, cl.Get(context.Background(),
		types.NamespacedName{Namespace: "default", Name: name}, got))
	return apimeta.FindStatusCondition(got.Status.Conditions, ConditionReady)
}

// buildStub wires a stubCR into a fake client and a VaultResource. Handlers
// are supplied per-test so each can drive a specific branch.
func buildStub(t *testing.T, obj *stubCR, h Handlers[*stubCR], opts ...func(*crfake.ClientBuilder)) (*VaultResource[*stubCR], client.Client) {
	t.Helper()
	scheme := stubScheme(t)
	b := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(obj).
		WithStatusSubresource(&stubCR{})
	for _, o := range opts {
		o(b)
	}
	cl := b.Build()
	return &VaultResource[*stubCR]{
		Client:        cl,
		Scheme:        scheme,
		Handlers:      h,
		FinalizerName: "stub.finalizer",
	}, cl
}

// A Ready=False message must name the bao object and openbao namespace. The
// namespace is the load-bearing half: it travels as an X-Vault-Namespace
// header, so it appears in no SDK error string and a multi-tenant failure
// would otherwise never say which tenant it happened in.
func TestReadyMessageNamesBaoIdentity(t *testing.T) {
	t.Parallel()

	t.Run("namespaced CR names its openbao namespace", func(t *testing.T) {
		t.Parallel()
		obj := &stubCR{
			ObjectMeta:  metav1.ObjectMeta{Name: "pki-int", Namespace: "default", Finalizers: []string{"stub.finalizer"}},
			OBNamespace: "team-a",
		}
		r, cl := buildStub(t, obj, Handlers[*stubCR]{
			NewInstance: func() *stubCR { return &stubCR{} },
			BaoGet: func(context.Context, *stubCR) (map[string]any, error) {
				return nil, errors.New("boom")
			},
		})
		_, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Namespace: "default", Name: "pki-int"},
		})
		require.NoError(t, err)

		cond := readyCond(t, cl, "pki-int")
		require.NotNil(t, cond)
		require.Equal(t, metav1.ConditionFalse, cond.Status)
		require.Contains(t, cond.Message, "boom", "the underlying error must survive")
		require.Contains(t, cond.Message, `bao object "pki-int"`)
		require.Contains(t, cond.Message, `openbao namespace "team-a"`)
	})

	t.Run("root-namespace CR says so explicitly", func(t *testing.T) {
		t.Parallel()
		obj := &stubCR{
			ObjectMeta: metav1.ObjectMeta{Name: "root-obj", Namespace: "default", Finalizers: []string{"stub.finalizer"}},
		}
		r, cl := buildStub(t, obj, Handlers[*stubCR]{
			NewInstance: func() *stubCR { return &stubCR{} },
			BaoGet: func(context.Context, *stubCR) (map[string]any, error) {
				return nil, errors.New("boom")
			},
		})
		_, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Namespace: "default", Name: "root-obj"},
		})
		require.NoError(t, err)

		cond := readyCond(t, cl, "root-obj")
		require.NotNil(t, cond)
		require.Contains(t, cond.Message, "openbao root namespace",
			`an empty namespace must not render as openbao namespace ""`)
	})

	t.Run("success message gets no suffix", func(t *testing.T) {
		t.Parallel()
		obj := &stubCR{
			ObjectMeta:  metav1.ObjectMeta{Name: "healthy", Namespace: "default", Finalizers: []string{"stub.finalizer"}},
			OBNamespace: "team-a",
		}
		r, cl := buildStub(t, obj, Handlers[*stubCR]{
			NewInstance: func() *stubCR { return &stubCR{} },
			BaoGet:      func(context.Context, *stubCR) (map[string]any, error) { return map[string]any{}, nil },
			BaoWrite:    func(context.Context, *stubCR) (StatusMutator[*stubCR], error) { return nil, nil },
		})
		_, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Namespace: "default", Name: "healthy"},
		})
		require.NoError(t, err)

		cond := readyCond(t, cl, "healthy")
		require.NotNil(t, cond)
		require.Equal(t, metav1.ConditionTrue, cond.Status)
		require.Empty(t, cond.Message,
			"Ready=True carries no message, so the suffix must not be appended to one")
	})

	// The suffix is composed inside the conflict-retry closure. Appending to
	// the captured msg parameter instead of a fresh local would duplicate it
	// once per retry.
	t.Run("conflict retry appends the suffix exactly once", func(t *testing.T) {
		t.Parallel()
		obj := &stubCR{
			ObjectMeta:  metav1.ObjectMeta{Name: "conflicted", Namespace: "default", Finalizers: []string{"stub.finalizer"}},
			OBNamespace: "team-a",
		}
		var patches int
		r, cl := buildStub(t, obj, Handlers[*stubCR]{
			NewInstance: func() *stubCR { return &stubCR{} },
			BaoGet: func(context.Context, *stubCR) (map[string]any, error) {
				return nil, errors.New("boom")
			},
		}, func(b *crfake.ClientBuilder) {
			b.WithInterceptorFuncs(interceptor.Funcs{
				SubResourcePatch: func(ctx context.Context, c client.Client, sub string,
					o client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
					patches++
					if patches == 1 {
						return apierrors.NewConflict(
							schema.GroupResource{Group: stubGV.Group, Resource: "stubcrs"}, o.GetName(),
							errors.New("simulated conflict"))
					}
					return c.Status().Patch(ctx, o, patch, opts...)
				},
			})
		})
		_, err := r.Reconcile(context.Background(), ctrl.Request{
			NamespacedName: types.NamespacedName{Namespace: "default", Name: "conflicted"},
		})
		require.NoError(t, err)
		require.Equal(t, 2, patches, "test must actually exercise the retry")

		cond := readyCond(t, cl, "conflicted")
		require.NotNil(t, cond)
		require.Equal(t, 1, strings.Count(cond.Message, "bao object"),
			"suffix appended once per patch attempt instead of once per message: %q", cond.Message)
	})
}

// R3: the base routes a missing bao object to the create path via
// errors.Is(err, ErrBaoNotFound). BaoOpErr wraps with %w so that keeps
// working. A %v here instead would silently turn every create into a
// permanent "object missing, never created" loop with no error surfaced.
func TestWrappedErrBaoNotFoundStillRoutesToCreate(t *testing.T) {
	t.Parallel()

	obj := &stubCR{
		ObjectMeta:  metav1.ObjectMeta{Name: "needs-create", Namespace: "default", Finalizers: []string{"stub.finalizer"}},
		OBNamespace: "team-a",
	}
	var writes int
	r, cl := buildStub(t, obj, Handlers[*stubCR]{
		NewInstance: func() *stubCR { return &stubCR{} },
		BaoGet: func(context.Context, *stubCR) (map[string]any, error) {
			return nil, BaoOpErr("reading policy", "editor", ErrBaoNotFound)
		},
		BaoWrite: func(context.Context, *stubCR) (StatusMutator[*stubCR], error) {
			writes++
			return nil, nil
		},
	})

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "needs-create"},
	})
	require.NoError(t, err)
	require.Equal(t, 1, writes,
		"a wrapped ErrBaoNotFound must still route to BaoWrite; if this is 0 the %w was lost")

	cond := readyCond(t, cl, "needs-create")
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status, "create path should have succeeded")
}

// drainEvents collects everything currently buffered in a FakeRecorder.
func drainEvents(rec *record.FakeRecorder) []string {
	var out []string
	for {
		select {
		case e := <-rec.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// failingThenHealthy flips BaoGet from error to success on a flag, so a test
// can drive a CR through break → repair without rebuilding the reconciler.
type flappingHandlers struct{ fail bool }

func (f *flappingHandlers) handlers() Handlers[*stubCR] {
	return Handlers[*stubCR]{
		NewInstance: func() *stubCR { return &stubCR{} },
		BaoGet: func(context.Context, *stubCR) (map[string]any, error) {
			if f.fail {
				return nil, errors.New("bao unreachable")
			}
			return map[string]any{}, nil
		},
		BaoWrite: func(context.Context, *stubCR) (StatusMutator[*stubCR], error) { return nil, nil },
	}
}

func stubWithRecorder(t *testing.T, obj *stubCR, h Handlers[*stubCR]) (*VaultResource[*stubCR], *record.FakeRecorder) {
	t.Helper()
	r, _ := buildStub(t, obj, h)
	rec := record.NewFakeRecorder(16)
	r.Recorder = rec
	return r, rec
}

func reconcileStub(t *testing.T, r *VaultResource[*stubCR], name string) {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: name},
	})
	require.NoError(t, err)
}

// seedReady returns a stubCR whose status already carries a Ready condition,
// so a single reconcile exercises a transition away from it.
//
// Reconciling twice does not work against the fake client: Get clears
// TypeMeta, so the patched object has no Kind and the fake's ManagedFields
// bookkeeping rejects any patch that changes something after an object's
// first. No-op patches slip through, which is why the "no transition" cases
// can loop. Real CRDs go through a real apiserver and are unaffected.
func seedReady(name string, status metav1.ConditionStatus, reason string) *stubCR {
	return &stubCR{
		ObjectMeta:  metav1.ObjectMeta{Name: name, Namespace: "default", Finalizers: []string{"stub.finalizer"}},
		OBNamespace: "team-a",
		Status: stubStatus{Conditions: []metav1.Condition{{
			Type:               ConditionReady,
			Status:             status,
			Reason:             reason,
			Message:            "seeded",
			LastTransitionTime: metav1.Now(),
		}}},
	}
}

// A Ready transition is the only durable trace of a failure that later
// self-heals: the patch that writes Ready=True erases the message explaining
// what went wrong.
func TestEventOnReadyTransition(t *testing.T) {
	t.Parallel()

	t.Run("healthy to failing warns", func(t *testing.T) {
		t.Parallel()
		h := &flappingHandlers{fail: true}
		r, rec := stubWithRecorder(t, seedReady("breaking", metav1.ConditionTrue, ReasonReconciled), h.handlers())

		reconcileStub(t, r, "breaking")
		events := drainEvents(rec)
		require.Len(t, events, 1, "entering failure emits exactly one event")
		require.Contains(t, events[0], "Warning")
		require.Contains(t, events[0], ReasonBaoError)
		require.Contains(t, events[0], "bao unreachable")
	})

	t.Run("failing to healthy records the recovery", func(t *testing.T) {
		t.Parallel()
		h := &flappingHandlers{fail: false}
		r, rec := stubWithRecorder(t, seedReady("recovering", metav1.ConditionFalse, ReasonBaoError), h.handlers())

		reconcileStub(t, r, "recovering")
		events := drainEvents(rec)
		require.Len(t, events, 1, "recovery emits exactly one event")
		require.Contains(t, events[0], "Normal")
		require.Contains(t, events[0], ReasonReconciled)

		cond := readyCond(t, r.Client, "recovering")
		require.NotNil(t, cond)
		require.Equal(t, metav1.ConditionTrue, cond.Status)
		require.Empty(t, cond.Message,
			"the recovery patch erases the failure message — the Event is the only trace left")
	})
}

// patchStatusOnce runs on every successful reconcile (PeriodicInterval 5m) and
// on every failed one (ErrorBackoff 30s). Without the transition gate a single
// tenant's 37 CRs would emit ~444 events an hour doing nothing wrong.
func TestNoEventWithoutTransition(t *testing.T) {
	t.Parallel()

	t.Run("repeated success is silent", func(t *testing.T) {
		t.Parallel()
		obj := &stubCR{ObjectMeta: metav1.ObjectMeta{Name: "steady", Namespace: "default", Finalizers: []string{"stub.finalizer"}}}
		h := &flappingHandlers{fail: false}
		r, rec := stubWithRecorder(t, obj, h.handlers())
		for i := 0; i < 3; i++ {
			reconcileStub(t, r, "steady")
		}
		require.Empty(t, drainEvents(rec), "a healthy CR must never emit")
	})

	t.Run("repeated identical failure emits once", func(t *testing.T) {
		t.Parallel()
		obj := &stubCR{ObjectMeta: metav1.ObjectMeta{Name: "wedged", Namespace: "default", Finalizers: []string{"stub.finalizer"}}}
		h := &flappingHandlers{fail: true}
		r, rec := stubWithRecorder(t, obj, h.handlers())
		for i := 0; i < 4; i++ {
			reconcileStub(t, r, "wedged")
		}
		require.Len(t, drainEvents(rec), 1,
			"a wedged CR emits on entry only, not once per ErrorBackoff")
	})
}

// A first-ever success is not a transition worth recording: Ready=True and
// status.baoWritten latch on the CR permanently, so an Event would duplicate
// durable state and expire in an hour. Onboarding a tenant must stay silent.
func TestNoEventOnFirstSuccess(t *testing.T) {
	t.Parallel()

	t.Run("new CR converging is silent", func(t *testing.T) {
		t.Parallel()
		obj := &stubCR{ObjectMeta: metav1.ObjectMeta{Name: "fresh", Namespace: "default", Finalizers: []string{"stub.finalizer"}}}
		h := &flappingHandlers{fail: false}
		r, rec := stubWithRecorder(t, obj, h.handlers())
		reconcileStub(t, r, "fresh")
		require.Empty(t, drainEvents(rec))
	})

	t.Run("new CR failing immediately still warns", func(t *testing.T) {
		t.Parallel()
		obj := &stubCR{ObjectMeta: metav1.ObjectMeta{Name: "fresh-bad", Namespace: "default", Finalizers: []string{"stub.finalizer"}}}
		h := &flappingHandlers{fail: true}
		r, rec := stubWithRecorder(t, obj, h.handlers())
		reconcileStub(t, r, "fresh-bad")
		events := drainEvents(rec)
		require.Len(t, events, 1, "a failure with no prior condition has no durable record either way")
		require.Contains(t, events[0], "Warning")
	})
}

// A reason change while still failing is meaningful and bounded (there are
// nine reasons), so it re-emits. A message-only change does not: messages
// carry varying detail and would defeat the gate.
func TestEventOnReasonChangeWhileFalse(t *testing.T) {
	t.Parallel()

	failing := func(t *testing.T, name string, seededReason string, err error) []string {
		t.Helper()
		r, rec := stubWithRecorder(t, seedReady(name, metav1.ConditionFalse, seededReason), Handlers[*stubCR]{
			NewInstance: func() *stubCR { return &stubCR{} },
			BaoGet:      func(context.Context, *stubCR) (map[string]any, error) { return nil, err },
		})
		reconcileStub(t, r, name)
		return drainEvents(rec)
	}

	t.Run("same reason, different message stays silent", func(t *testing.T) {
		t.Parallel()
		events := failing(t, "same-reason", ReasonInternalError,
			fmt.Errorf("%w: a different internal detail", ErrInternal))
		require.Empty(t, events,
			"messages carry varying detail; comparing them would defeat the gate")
	})

	t.Run("reason change re-emits", func(t *testing.T) {
		t.Parallel()
		events := failing(t, "new-reason", ReasonInternalError,
			fmt.Errorf("%w: immutable", ErrInvalidSpec))
		require.Len(t, events, 1, "a reason change is meaningful and bounded — nine reasons exist")
		require.Contains(t, events[0], ReasonInvalid)
	})
}

// The Event is emitted outside the conflict-retry closure. Emitting inside
// would fire one per attempt for a single transition.
func TestNoDuplicateEventOnConflictRetry(t *testing.T) {
	t.Parallel()

	obj := &stubCR{
		ObjectMeta: metav1.ObjectMeta{Name: "retried", Namespace: "default", Finalizers: []string{"stub.finalizer"}},
	}
	scheme := stubScheme(t)
	var patches int
	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(obj).
		WithStatusSubresource(&stubCR{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, sub string,
				o client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				patches++
				if patches == 1 {
					return apierrors.NewConflict(
						schema.GroupResource{Group: stubGV.Group, Resource: "stubcrs"}, o.GetName(),
						errors.New("simulated conflict"))
				}
				return c.Status().Patch(ctx, o, patch, opts...)
			},
		}).
		Build()

	rec := record.NewFakeRecorder(16)
	r := &VaultResource[*stubCR]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: "stub.finalizer",
		Recorder:      rec,
		Handlers: Handlers[*stubCR]{
			NewInstance: func() *stubCR { return &stubCR{} },
			BaoGet: func(context.Context, *stubCR) (map[string]any, error) {
				return nil, errors.New("boom")
			},
		},
	}

	reconcileStub(t, r, "retried")
	require.Equal(t, 2, patches, "test must actually exercise the retry")
	require.Len(t, drainEvents(rec), 1, "one transition must produce one event, not one per attempt")
}

// 26 sites across the repo build VaultResource as a struct literal rather than
// via New, so Recorder is nil there. A nil-interface method call would panic.
func TestNilRecorderDoesNotPanic(t *testing.T) {
	t.Parallel()

	t.Run("failure transition", func(t *testing.T) {
		t.Parallel()
		r, _ := buildStub(t, seedReady("no-rec-fail", metav1.ConditionTrue, ReasonReconciled),
			(&flappingHandlers{fail: true}).handlers())
		require.Nil(t, r.Recorder, "this test is meaningless if the harness sets a recorder")

		reconcileStub(t, r, "no-rec-fail")
		cond := readyCond(t, r.Client, "no-rec-fail")
		require.NotNil(t, cond)
		require.Equal(t, metav1.ConditionFalse, cond.Status)
	})

	t.Run("recovery transition", func(t *testing.T) {
		t.Parallel()
		r, _ := buildStub(t, seedReady("no-rec-ok", metav1.ConditionFalse, ReasonBaoError),
			(&flappingHandlers{fail: false}).handlers())
		require.Nil(t, r.Recorder)

		reconcileStub(t, r, "no-rec-ok")
		cond := readyCond(t, r.Client, "no-rec-ok")
		require.NotNil(t, cond)
		require.Equal(t, metav1.ConditionTrue, cond.Status,
			"reconcile must converge normally with no recorder attached")
	})
}

// The condition is the authoritative surface and keeps the full text; the
// Event is rendered in kubectl tables and is truncated.
func TestEventMessageTruncated(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", maxEventMsgLen*2)
	obj := &stubCR{ObjectMeta: metav1.ObjectMeta{Name: "verbose", Namespace: "default", Finalizers: []string{"stub.finalizer"}}}
	r, rec := stubWithRecorder(t, obj, Handlers[*stubCR]{
		NewInstance: func() *stubCR { return &stubCR{} },
		BaoGet: func(context.Context, *stubCR) (map[string]any, error) {
			return nil, errors.New(long)
		},
	})

	reconcileStub(t, r, "verbose")
	events := drainEvents(rec)
	require.Len(t, events, 1)
	require.Less(t, len(events[0]), len(long), "event message must be truncated")
	require.Contains(t, events[0], "full message in status.conditions")

	cond := readyCond(t, r.Client, "verbose")
	require.NotNil(t, cond)
	require.Contains(t, cond.Message, long, "the condition must keep the untruncated text")
}
