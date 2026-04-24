// Package resource provides the shared reconcile wrapper that all VCO-origin
// primitive controllers use. It owns finalizer handling, drift detection,
// status condition writes, and error classification.
//
// See docs/plans/PLAN-vco-st1-foundation-policy.md for the design contract.
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

// Condition type written by the shared base. Primitive-specific controllers
// may add further conditions (e.g. IntermediateSigned for PKI) on top.
const ConditionReady = "Ready"

// Timing constants; match the existing ClusterAuth pattern.
const (
	PeriodicInterval = 5 * time.Minute
	ErrorBackoff     = 30 * time.Second
)

// VaultCR is the interface a CR must satisfy to be reconciled by VaultResource.
// Embeds client.Object (runtime.Object + metav1.Object), VaultObject (the VCO
// contract), and ConditionsAware (status condition helpers).
type VaultCR interface {
	client.Object
	vaultobject.VaultObject
	vaultobject.ConditionsAware
}

// Handlers carries the primitive-specific bao I/O. Each story's controller
// constructs one and passes it to NewVaultResource.
type Handlers[T VaultCR] struct {
	// NewInstance returns a zero-value of the concrete CR type (e.g. &Policy{}).
	NewInstance func() T

	// BaoGet reads the current state from OpenBao and returns it as a map
	// comparable with GetPayload(). Return ErrBaoNotFound if the object does
	// not exist on the server (drives the create-not-update path).
	BaoGet func(ctx context.Context, obj T) (map[string]any, error)

	// BaoWrite creates or updates the object in OpenBao.
	BaoWrite func(ctx context.Context, obj T) error

	// BaoDelete removes the object from OpenBao. 404 should be treated as
	// success by the implementation (idempotent delete).
	BaoDelete func(ctx context.Context, obj T) error
}

// ErrBaoNotFound is returned by BaoGet when the primitive's bao-side object
// does not exist. The base treats this as "needs to be created" rather than
// an error.
var ErrBaoNotFound = errors.New("bao object not found")

// VaultResource is the shared reconciler. Each primitive wraps one by
// composition, adding SetupWithManager with its own For(&CRKind{}) and
// whatever predicates/watches that primitive needs.
type VaultResource[T VaultCR] struct {
	client.Client
	Scheme        *runtime.Scheme
	Log           logr.Logger
	Handlers      Handlers[T]
	FinalizerName string
}

// New constructs a VaultResource. FinalizerName follows the Kubernetes
// convention <resource>.<group>/finalizer; each primitive supplies its own.
func New[T VaultCR](mgr ctrl.Manager, finalizer string, h Handlers[T]) *VaultResource[T] {
	return &VaultResource[T]{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Log:           ctrl.Log.WithName("vaultobject"),
		Handlers:      h,
		FinalizerName: finalizer,
	}
}

// Reconcile implements the shared lifecycle. See plan's Reconciler design.
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

	// Finalizer add on first reconcile. Requeue explicitly: with
	// GenerationChangedPredicate on the watch, the metadata-only Update
	// below is filtered out and won't trigger a follow-up reconcile on its
	// own.
	if !controllerutil.ContainsFinalizer(obj, r.FinalizerName) {
		controllerutil.AddFinalizer(obj, r.FinalizerName)
		if err := r.Update(ctx, obj); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Validate.
	if ok, err := obj.IsValid(); !ok {
		msg := "invalid spec"
		if err != nil {
			msg = err.Error()
		}
		_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ReasonInvalid, msg)
		return ctrl.Result{}, nil // no requeue; user must fix spec
	}

	// Prepare any server-dependent values (e.g. accessor substitution).
	if err := obj.PrepareInternalValues(ctx, obj); err != nil {
		_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ClassifyErr(err), err.Error())
		return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
	}
	if err := obj.PrepareTLSConfig(ctx, obj); err != nil {
		_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ClassifyErr(err), err.Error())
		return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
	}

	// Drift check + create-or-update.
	current, err := r.Handlers.BaoGet(ctx, obj)
	switch {
	case errors.Is(err, ErrBaoNotFound):
		if err := r.Handlers.BaoWrite(ctx, obj); err != nil {
			l.Error(err, "bao write failed on create path")
			_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ClassifyErr(err), err.Error())
			return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
		}
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
		}
	}

	_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionTrue, ReasonReconciled, "")
	return ctrl.Result{RequeueAfter: PeriodicInterval}, nil
}

func (r *VaultResource[T]) handleDelete(ctx context.Context, obj T, l logr.Logger) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(obj, r.FinalizerName) {
		return ctrl.Result{}, nil
	}

	if obj.IsDeletable() {
		if err := r.Handlers.BaoDelete(ctx, obj); err != nil {
			l.Error(err, "bao delete failed")
			_ = r.setReady(ctx, client.ObjectKeyFromObject(obj), metav1.ConditionFalse, ClassifyErr(err), err.Error())
			return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
		}
	}

	controllerutil.RemoveFinalizer(obj, r.FinalizerName)
	if err := r.Update(ctx, obj); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// setReady writes a Ready condition on the CR via conflict-safe merge patch.
// Pattern mirrors internal/controller/clusterauth/clusterauth_controller.go:setAuthCond.
func (r *VaultResource[T]) setReady(ctx context.Context, key client.ObjectKey, status metav1.ConditionStatus, reason, msg string) error {
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

		return r.Status().Patch(ctx, cur, client.MergeFrom(origObj))
	})
}
