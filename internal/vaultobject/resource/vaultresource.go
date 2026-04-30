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
	vaultobject.RenameTracker
}

// Handlers carries the primitive-specific bao I/O.
type Handlers[T VaultCR] struct {
	// NewInstance returns a zero-value of the concrete CR type.
	NewInstance func() T

	// BaoGet reads the current state from OpenBao. Return ErrBaoNotFound
	// if the object does not exist on the server.
	BaoGet func(ctx context.Context, obj T) (map[string]any, error)

	// BaoWrite creates or updates the object in OpenBao. The optional
	// returned closure is invoked on the freshly-fetched CR during the
	// post-write status patch so primitives can stamp server-derived
	// fields (e.g. PKI CA serial, last-written path) atomically with
	// Ready=True. Returning a nil closure is equivalent to "no extra
	// status mutation".
	//
	// The closure runs inside the base's conflict-safe retry loop, so
	// any mutation it does on the passed CR is persisted via the same
	// MergeFrom patch that flips baoWritten=true and SetLastWritten.
	// This eliminates the side-channel `cl.Status().Patch` pattern,
	// where a swallowed patch error left status fields stranded.
	BaoWrite func(ctx context.Context, obj T) (StatusMutator[T], error)

	// BaoDelete removes the object from OpenBao at the CR's current bao
	// identity. Implementations should be idempotent on 404.
	BaoDelete func(ctx context.Context, obj T) error

	// BaoDeleteIdentity removes a previous bao object after a rename. The
	// (name, namespace) pair is the identity the CR last successfully wrote,
	// recovered from RenameTracker.LastWrittenBaoName /
	// LastWrittenOpenBaoNamespace. Implementations should reach the same
	// HTTP endpoint shape as BaoDelete and be idempotent on 404.
	BaoDeleteIdentity func(ctx context.Context, obj T, name, namespace string) error

	// CheckCollision returns ErrNameCollision when another CR (different
	// UID) already owns the bao identity this CR targets. The base calls
	// it before BaoGet on every reconcile so the loser short-circuits
	// without ever observing or touching bao state. Without this, a CR
	// whose desired payload happens to match the winner's bao state —
	// either because two CRs share an identical spec, or because the
	// primitive's create call carries no body to drift-check against —
	// would silently "adopt" the existing object: drift check sees
	// state already matches, BaoWrite never fires, the collision check
	// buried inside BaoWrite never runs.
	//
	// Optional. nil means the primitive has no need to detect collisions
	// (single-instance primitives, or primitives whose bao identity is
	// guaranteed unique by spec shape).
	CheckCollision func(ctx context.Context, obj T) error

	// Backfill is called after a no-drift BaoGet (state already matches
	// desired, no BaoWrite). Primitives use it to populate status
	// fields derived from observed bao state — for example, a CR
	// adopting a CA that an earlier reconcile created without
	// stamping status.Phase, or a controller upgrade that introduced
	// new status fields. Returning a nil mutator means "nothing to
	// backfill"; a non-nil mutator runs in the same status patch as
	// Ready=True.
	//
	// Optional. Without this hook, status fields populated only by
	// BaoWrite's mutator stay stranded if the create-or-update path
	// is never re-entered.
	Backfill func(obj T, current map[string]any) StatusMutator[T]
}

// StatusMutator is the optional closure a primitive's BaoWrite returns
// to stamp server-derived status fields onto the freshly-fetched CR
// during the post-write status patch. nil = no mutation.
type StatusMutator[T VaultCR] func(T)

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

	// Prepare any server-dependent values (e.g. accessor substitution,
	// label-selector resolution, secret-ref dereferencing). Failures
	// here are controller-side (k8s lookups, in-process state
	// resolution), not bao failures — classify as ReasonInternalError so
	// dashboards don't conflate them with bao outages.
	//
	// The kube client is exposed to PrepareInternalValues via the
	// reconcile context under the untyped "kubeClient" key. Primitives
	// that need to query the apiserver during preparation read it back
	// without an interface signature change; primitives that don't need
	// it ignore the value and pay nothing. Untyped string key follows
	// the upstream VCO contract; staticcheck flags it on the line below.
	//nolint:staticcheck // untyped context key matches upstream VCO contract
	ctx = context.WithValue(ctx, "kubeClient", r.Client)
	if err := obj.PrepareInternalValues(ctx, obj); err != nil {
		_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ReasonInternalError, err.Error())
		return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
	}
	if err := obj.PrepareTLSConfig(ctx, obj); err != nil {
		_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ReasonInternalError, err.Error())
		return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
	}

	// Collision check runs before BaoGet so a CR that loses the tie-break
	// short-circuits without ever reading or writing bao. Lifting it out
	// of BaoWrite plugs a hole where two CRs targeting the same bao
	// identity with payloads that match bao's current state both claim
	// Ready=True — drift check sees state matches, BaoWrite never fires,
	// the in-BaoWrite collision check never runs. Empty-payload primitives
	// hit this universally; primitives whose payload is non-empty hit
	// it whenever two CRs share the same spec.
	if r.Handlers.CheckCollision != nil {
		if err := r.Handlers.CheckCollision(ctx, obj); err != nil {
			_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ClassifyErr(err), err.Error())
			// A real collision (ErrNameCollision) is a stable user-driven
			// state, so the loser polls at PeriodicInterval — fast enough
			// to pick up ownership soon after the winner is deleted, slow
			// enough not to busy-loop. Anything else (apiserver list
			// failure, internal error) is transient and warrants
			// ErrorBackoff to recover quickly.
			if errors.Is(err, ErrNameCollision) {
				return ctrl.Result{RequeueAfter: PeriodicInterval}, nil
			}
			return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
		}
	}

	// Drift check + create-or-update. wroteThisPass is set when we just
	// performed a successful BaoWrite; the post-write status patch then
	// flips status.baoWritten=true so the deletion path can distinguish
	// "never wrote" from "wrote then drifted". A non-nil mutator from
	// BaoWrite is applied on the freshly-fetched CR during the same
	// status patch, so primitives can stamp server-derived fields
	// atomically with Ready=True.
	current, err := r.Handlers.BaoGet(ctx, obj)
	var (
		wroteThisPass bool
		mutator       StatusMutator[T]
	)
	switch {
	case errors.Is(err, ErrBaoNotFound):
		mutator, err = r.Handlers.BaoWrite(ctx, obj)
		if err != nil {
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
			mutator, err = r.Handlers.BaoWrite(ctx, obj)
			if err != nil {
				l.Error(err, "bao write failed on update path")
				_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ClassifyErr(err), err.Error())
				return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
			}
			wroteThisPass = true
		} else if r.Handlers.Backfill != nil {
			// State matches desired; ask the primitive whether any
			// status fields need to catch up to observed bao state.
			mutator = r.Handlers.Backfill(obj, current)
		}
	}

	// Rename cleanup: if the previously-written bao identity differs from
	// the current one, the user changed spec.name (or spec.openbaoNamespace).
	// The new identity has just been written above; delete the old object
	// so the rename doesn't leave an orphan. A failure here surfaces in
	// logs and via Ready=False so the user knows about the orphan; we
	// don't advance LastWritten until the cleanup succeeds, so the next
	// reconcile retries.
	prevName, prevNS := obj.LastWrittenBaoName(), obj.LastWrittenOpenBaoNamespace()
	curName, curNS := obj.BaoName(), obj.OpenBaoNamespace()
	identityChanged := prevName != "" && (prevName != curName || prevNS != curNS)
	if identityChanged && r.Handlers.BaoDeleteIdentity != nil {
		if !obj.IsDeletable() {
			// Primitives that opt out of bao-side cleanup on CR delete
			// (e.g. PKI root CAs, where deleting the mount loses the
			// private key forever) must not have rename either: a
			// rename of an IsDeletable=false type produces a duplicate
			// bao object at the new identity, the old one is left in
			// place by design. Log the orphan so audit shows what was
			// kept, then advance LastWritten so the controller stops
			// trying to clean up the previous identity on every loop.
			l.Info("IsDeletable=false; skipping rename cleanup of previous bao identity (intentional orphan)",
				"previousName", prevName, "previousOpenBaoNamespace", prevNS,
				"newName", curName, "newOpenBaoNamespace", curNS)
		} else {
			if err := r.Handlers.BaoDeleteIdentity(ctx, obj, prevName, prevNS); err != nil {
				l.Error(err, "bao delete failed on rename cleanup path",
					"previousName", prevName, "previousOpenBaoNamespace", prevNS)
				_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ClassifyErr(err),
					fmt.Sprintf("rename cleanup of previous bao identity %q in namespace %q failed: %v",
						prevName, prevNS, err))
				return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
			}
		}
	}

	_ = r.setReadyAndMaybeMarkWritten(ctx, req.NamespacedName,
		metav1.ConditionTrue, ReasonReconciled, "", wroteThisPass, curName, curNS, mutator)
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
	return r.patchStatusOnce(ctx, key, status, reason, msg, false, "", "", nil)
}

// setReadyAndMaybeMarkWritten patches Ready and, when wrote=true, also
// flips status.baoWritten=true and records the bao identity (curName,
// curNS) into status.lastWrittenBaoName / status.lastWrittenOpenBaoNamespace.
// All three fields go in the same MergeFrom patch so the transition is
// atomic from the apiserver's perspective: a crash between two separate
// patches cannot leave the CR with Ready=True but baoWritten=false, nor
// with baoWritten=true but no recorded identity (the latter would defeat
// rename cleanup on the next reconcile).
//
// When wrote=false (state already matched bao), the LastWritten fields
// are still refreshed so a controller upgrade onto an older CR — written
// before this field existed — can backfill the identity on the first
// reconcile that finds bao already in the desired state.
func (r *VaultResource[T]) setReadyAndMaybeMarkWritten(ctx context.Context, key client.ObjectKey, status metav1.ConditionStatus, reason, msg string, wrote bool, curName, curNS string, mutator StatusMutator[T]) error {
	err := r.patchStatusOnce(ctx, key, status, reason, msg, wrote, curName, curNS, mutator)
	if err != nil && !apierrors.IsNotFound(err) {
		log.FromContext(ctx).Error(err, "failed to write Ready+baoWritten+identity status",
			"name", key.Name, "namespace", key.Namespace, "reason", reason)
	}
	return err
}

// patchStatusOnce assembles the status patch in a conflict-safe retry
// loop. The mutator (when non-nil) runs on the freshly-fetched CR
// after baoWritten + identity advancement, so primitive-specific
// status fields land in the same MergeFrom patch — no side-channel
// status writes that can silently fail.
func (r *VaultResource[T]) patchStatusOnce(ctx context.Context, key client.ObjectKey, status metav1.ConditionStatus, reason, msg string, markWritten bool, curName, curNS string, mutator StatusMutator[T]) error {
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

		// Record bao identity whenever the caller passes a non-empty
		// name. curName is empty only on the error / setReady-only
		// paths, which reuse this method via a wrapper that forwards "".
		if curName != "" {
			cur.SetLastWrittenBaoIdentity(curName, curNS)
		}

		// Apply primitive-specific status mutations from BaoWrite's
		// returned closure. Runs last so the closure can read the
		// fields above if it wants.
		if mutator != nil {
			mutator(cur)
		}

		return r.Status().Patch(ctx, cur, client.MergeFrom(origObj))
	})
}
