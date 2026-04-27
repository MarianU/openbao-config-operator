// Package resource provides the shared reconcile wrapper that primitive
// controllers compose with. It owns finalizer handling, drift detection,
// status condition writes, and error classification.
package resource

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject"
)

// ConditionReady is the canonical condition type written by the base.
const ConditionReady = "Ready"

const (
	PeriodicInterval = 5 * time.Minute
	ErrorBackoff     = 30 * time.Second
)

// VaultCR is the interface a CR must satisfy to be reconciled by VaultResource.
type VaultCR interface {
	client.Object
	vaultobject.VaultObject
	vaultobject.ConditionsAware
	vaultobject.WriteTracker
}

// Handlers carries the primitive-specific bao I/O.
type Handlers[T VaultCR] struct {
	// NewInstance returns a zero-value of the concrete CR type.
	NewInstance func() T

	// BaoGet reads the current state from OpenBao. Return ErrBaoNotFound
	// if the object does not exist on the server.
	BaoGet func(ctx context.Context, obj T) (map[string]any, error)

	// BaoWrite creates or updates the object in OpenBao.
	BaoWrite func(ctx context.Context, obj T) error

	// BaoDelete removes the object from OpenBao. Implementations should be
	// idempotent on 404.
	BaoDelete func(ctx context.Context, obj T) error
}

// ErrBaoNotFound is returned by BaoGet when the primitive's bao-side object
// does not exist. The base treats this as "needs to be created".
var ErrBaoNotFound = errors.New("bao object not found")

// VaultResource is the shared reconciler. Primitives wrap it by composition.
type VaultResource[T VaultCR] struct {
	client.Client
	Scheme        *runtime.Scheme
	Handlers      Handlers[T]
	FinalizerName string
}

// New constructs a VaultResource. FinalizerName follows the Kubernetes
// convention <resource>.<group>/finalizer.
func New[T VaultCR](mgr ctrl.Manager, finalizer string, h Handlers[T]) *VaultResource[T] {
	return &VaultResource[T]{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Handlers:      h,
		FinalizerName: finalizer,
	}
}

// Reconcile implements the shared lifecycle.
func (r *VaultResource[T]) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx).WithValues("name", req.Name, "namespace", req.Namespace)

	obj := r.Handlers.NewInstance()
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Deletion path.
	if !obj.GetDeletionTimestamp().IsZero() {
		return r.handleDelete(ctx, obj, l)
	}

	// Finalizer add on first reconcile. Requeue explicitly so the next pass
	// runs the create/update logic; we cannot rely on the metadata-only
	// Update below to enqueue us, because callers commonly install a
	// generation- or spec-scoped predicate on the watch that filters
	// finalizer-only changes out.
	if !controllerutil.ContainsFinalizer(obj, r.FinalizerName) {
		controllerutil.AddFinalizer(obj, r.FinalizerName)
		if err := r.Update(ctx, obj); err != nil {
			l.Error(err, "failed to add finalizer; CR will not progress until this succeeds")
			_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ClassifyErr(err), err.Error())
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Validate. IsValid() must return (true, nil) on accept or (false, err)
	// on reject — (false, nil) is an implementer bug because the user has
	// no way to learn why their spec was refused. Log loudly so the bug
	// surfaces in a primitive's tests, and surface a generic message so
	// the CR doesn't get stuck with an empty Ready=False reason.
	if ok, err := obj.IsValid(); !ok {
		var msg string
		switch {
		case err != nil:
			msg = err.Error()
		default:
			l.Error(nil, "IsValid returned (false, nil); primitive must return a non-nil error explaining why",
				"type", fmt.Sprintf("%T", obj))
			msg = "invalid spec (no reason provided — implementer bug, see operator logs)"
		}
		_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ReasonInvalid, msg)
		return ctrl.Result{}, nil // no requeue; user must fix spec
	}

	// Prepare any server-dependent values (e.g. accessor substitution).
	// Failures here are controller-side (k8s lookups, in-process state
	// resolution), not bao failures — classify as ReasonInternalError so
	// dashboards don't conflate them with bao outages.
	if err := obj.PrepareInternalValues(ctx, obj); err != nil {
		_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ReasonInternalError, err.Error())
		return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
	}
	if err := obj.PrepareTLSConfig(ctx, obj); err != nil {
		_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ReasonInternalError, err.Error())
		return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
	}

	// Drift check + create-or-update. wroteThisPass is set when we just
	// performed a successful BaoWrite; the post-write status patch then
	// flips status.baoWritten=true so the deletion path can distinguish
	// "never wrote" from "wrote then drifted".
	current, err := r.Handlers.BaoGet(ctx, obj)
	var wroteThisPass bool
	switch {
	case errors.Is(err, ErrBaoNotFound):
		if err := r.Handlers.BaoWrite(ctx, obj); err != nil {
			l.Error(err, "bao write failed on create path")
			_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ClassifyErr(err), err.Error())
			return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
		}
		wroteThisPass = true
	case err != nil:
		l.Error(err, "bao get failed")
		_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ClassifyErr(err), err.Error())
		return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
	default:
		if !obj.IsEquivalentToDesiredState(current) {
			if err := r.Handlers.BaoWrite(ctx, obj); err != nil {
				l.Error(err, "bao write failed on update path")
				_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ClassifyErr(err), err.Error())
				return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
			}
			wroteThisPass = true
		}
	}

	_ = r.setReadyAndMaybeMarkWritten(ctx, req.NamespacedName,
		metav1.ConditionTrue, ReasonReconciled, "", wroteThisPass)
	return ctrl.Result{RequeueAfter: PeriodicInterval}, nil
}

func (r *VaultResource[T]) handleDelete(ctx context.Context, obj T, l logr.Logger) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(obj, r.FinalizerName) {
		return ctrl.Result{}, nil
	}

	switch {
	case !obj.IsDeletable():
		// Primitives can opt out of bao-side cleanup (e.g. a PKI root CA
		// that must persist beyond the CR's lifetime). The k8s CR is still
		// finalized and removed; the bao object is intentionally orphaned.
		// Log so this isn't silent — operator and audit logs need to show
		// what was left behind.
		l.Info("IsDeletable=false; releasing finalizer without removing bao object (intentional orphan)",
			"finalizer", r.FinalizerName)
	case !obj.IsBaoWritten():
		// CR has never successfully written to bao — nothing to clean
		// up. The status.baoWritten field is the durable signal: it
		// only flips true after a successful BaoWrite, and once set
		// is never cleared. This avoids the orphan-leak that the
		// transient "is Ready=True right now" check produced when a
		// CR's Ready flipped True→False after a successful write.
	default:
		if err := r.Handlers.BaoDelete(ctx, obj); err != nil {
			l.Error(err, "bao delete failed")
			_ = r.setReady(ctx, client.ObjectKeyFromObject(obj), metav1.ConditionFalse, ClassifyErr(err), err.Error())
			return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
		}
	}

	controllerutil.RemoveFinalizer(obj, r.FinalizerName)
	if err := r.Update(ctx, obj); err != nil {
		// CR is being deleted, so writing Ready=False would race the
		// removal; just log so the failure is operationally visible.
		// Controller-runtime requeues on the returned error.
		l.Error(err, "failed to remove finalizer; CR will remain in Terminating until next reconcile",
			"finalizer", r.FinalizerName)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// setReady writes a Ready condition on the CR via conflict-safe merge patch.
//
// Callers discard the returned error (status-write failures should not gate
// the reconcile result), so this method logs non-NotFound errors itself.
// IsNotFound is the benign deletion-race case where the CR is already gone;
// logging it would be noise.
func (r *VaultResource[T]) setReady(ctx context.Context, key client.ObjectKey, status metav1.ConditionStatus, reason, msg string) error {
	err := r.setReadyOnce(ctx, key, status, reason, msg)
	if err != nil && !apierrors.IsNotFound(err) {
		log.FromContext(ctx).Error(err, "failed to write Ready status condition",
			"name", key.Name, "namespace", key.Namespace, "reason", reason)
	}
	return err
}

func (r *VaultResource[T]) setReadyOnce(ctx context.Context, key client.ObjectKey, status metav1.ConditionStatus, reason, msg string) error {
	return r.patchStatusOnce(ctx, key, status, reason, msg, false)
}

// setReadyAndMaybeMarkWritten patches Ready and, when wrote=true, also
// flips status.baoWritten=true in the same status patch. Combining both
// fields into one MergeFrom patch keeps the transition atomic from the
// apiserver's perspective: a crash between two separate patches cannot
// leave the CR with Ready=True but baoWritten=false.
func (r *VaultResource[T]) setReadyAndMaybeMarkWritten(ctx context.Context, key client.ObjectKey, status metav1.ConditionStatus, reason, msg string, wrote bool) error {
	err := r.patchStatusOnce(ctx, key, status, reason, msg, wrote)
	if err != nil && !apierrors.IsNotFound(err) {
		log.FromContext(ctx).Error(err, "failed to write Ready+baoWritten status",
			"name", key.Name, "namespace", key.Namespace, "reason", reason)
	}
	return err
}

func (r *VaultResource[T]) patchStatusOnce(ctx context.Context, key client.ObjectKey, status metav1.ConditionStatus, reason, msg string, markWritten bool) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cur := r.Handlers.NewInstance()
		if err := r.Get(ctx, key, cur); err != nil {
			return err
		}
		origObj, ok := cur.DeepCopyObject().(client.Object)
		if !ok {
			return fmt.Errorf("deep copy of %T is not a client.Object", cur)
		}

		conds := cur.GetConditions()
		apimeta.SetStatusCondition(&conds, metav1.Condition{
			Type:               ConditionReady,
			Status:             status,
			Reason:             reason,
			Message:            msg,
			ObservedGeneration: cur.GetGeneration(),
		})
		cur.SetConditions(conds)

		if markWritten {
			cur.MarkBaoWritten()
		}

		return r.Status().Patch(ctx, cur, client.MergeFrom(origObj))
	})
}
