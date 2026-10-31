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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/stakater/openbao-config-operator/internal/vaultobject"
)

// EventRecorder reports a denied write to its own log rather than to the
// caller, so without this grant events silently never appear.
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// ConditionReady is the canonical condition type written by the base.
const ConditionReady = "Ready"

// ConditionSynced reports whether the last reconcile could talk to OpenBao
// and the object matches/advanced desired state. A crossplane-parity signal:
// it is False only on a real reconcile failure (denied/unreachable/invalid),
// so Argo health can map Synced=False -> Degraded — the "I cannot apply this
// resource to OpenBao" signal — without flagging an intermediate state that
// is progressing normally.
const ConditionSynced = "Synced"

// ConditionProgressing reports an in-flight, not-yet-converged state (e.g. an
// intermediate CA awaiting an external signature). It is True only for
// non-fatal "waiting" reasons; a hard failure sets Progressing=False (it is
// stuck, not progressing) and relies on Synced=False + Ready=False instead.
const ConditionProgressing = "Progressing"

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
// does not exist. The base treats this as "needs to be created". The text
// names this layer to keep it traceable apart from baoclient.ErrNotFound.
var ErrBaoNotFound = errors.New("reconciler: bao object does not exist")

// VaultResource is the shared reconciler. Primitives wrap it by composition.
type VaultResource[T VaultCR] struct {
	client.Client
	Scheme        *runtime.Scheme
	Handlers      Handlers[T]
	FinalizerName string
	// Recorder emits Events on Ready transitions and bao-object
	// orphaning. Optional: nil skips emission (test struct literals).
	// All emission is nil-guarded — never call r.Recorder.Event
	// directly.
	Recorder record.EventRecorder
}

// event emits via Recorder when one is wired; the nil-guard keeps the
// field genuinely optional.
func (r *VaultResource[T]) event(obj client.Object, eventtype, reason, message string) {
	if r.Recorder != nil {
		r.Recorder.Event(obj, eventtype, reason, message)
	}
}

// New constructs a VaultResource. FinalizerName follows the Kubernetes
// convention <resource>.<group>/finalizer.
func New[T VaultCR](mgr ctrl.Manager, finalizer string, h Handlers[T]) *VaultResource[T] {
	return &VaultResource[T]{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Handlers:      h,
		FinalizerName: finalizer,
		Recorder:      EventRecorderFor(mgr),
	}
}

// EventRecorderFor returns the recorder the base emits Ready transitions
// through. Primitives that report an Event of their own take it from here, so
// the source name and the events-API choice have one site.
//
// GetEventRecorder writes events.k8s.io/v1 instead of core/v1; migrating needs
// that RBAC grant deployed first or Events stop appearing entirely.
func EventRecorderFor(mgr ctrl.Manager) record.EventRecorder {
	//nolint:staticcheck // SA1019: migration gated on RBAC, see above.
	return mgr.GetEventRecorderFor("openbao-config-operator")
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

	// Drift check + create-or-update. Every branch reaching the success
	// patch has confirmed the bao object exists under this CR's
	// identity — freshly written, or found already matching (adoption).
	// Both mark status.baoWritten: the deletion path needs "an object
	// exists", not "this CR wrote it", or a re-applied CR could never
	// tear down the orphan it adopted. Adoption-marking is only safe
	// under a collision guard (a tie-break loser short-circuits before
	// this point); without CheckCollision two same-identity CRs would
	// both adopt and either delete would pull the object out from under
	// the other — so nil-hook primitives latch on writes only. The
	// mutator from BaoWrite/Backfill runs inside the same status patch.
	current, err := r.Handlers.BaoGet(ctx, obj)
	var (
		wrote   bool
		mutator StatusMutator[T]
	)
	switch {
	case errors.Is(err, ErrBaoNotFound):
		mutator, err = r.Handlers.BaoWrite(ctx, obj)
		if err != nil {
			l.Error(err, "bao write failed on create path")
			_ = r.setReady(ctx, req.NamespacedName, metav1.ConditionFalse, ClassifyErr(err), err.Error())
			return ctrl.Result{RequeueAfter: ErrorBackoff}, nil
		}
		wrote = true
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
			wrote = true
		} else if r.Handlers.Backfill != nil {
			// State matches desired; ask the primitive whether any
			// status fields need to catch up to observed bao state.
			mutator = r.Handlers.Backfill(obj, current)
		}
	}
	markOwnership := wrote || r.Handlers.CheckCollision != nil

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
			// Bao-side cleanup disabled — the rename writes the new bao
			// identity and intentionally keeps the previous object.
			// Log + Event the orphan, then advance LastWritten so the
			// skipped cleanup is not retried every loop.
			l.Info("bao-side cleanup disabled; skipping rename cleanup of previous bao identity (intentional orphan)",
				"previousName", prevName, "previousOpenBaoNamespace", prevNS,
				"newName", curName, "newOpenBaoNamespace", curNS)
			r.event(obj, corev1.EventTypeNormal, "BaoObjectOrphaned",
				fmt.Sprintf("rename skipped bao-side cleanup of the previous object %q in openbao namespace %q",
					prevName, prevNS))
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

	_ = r.setReadyAndMarkWritten(ctx, req.NamespacedName,
		metav1.ConditionTrue, ReasonReconciled, "", markOwnership, curName, curNS, mutator)
	return ctrl.Result{RequeueAfter: PeriodicInterval}, nil
}

func (r *VaultResource[T]) handleDelete(ctx context.Context, obj T, l logr.Logger) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(obj, r.FinalizerName) {
		return ctrl.Result{}, nil
	}

	switch {
	case !obj.IsBaoWritten():
		// Never confirmed a bao object — nothing to clean up or orphan.
		// Precedes !IsDeletable() so a CR that never reconciled
		// successfully doesn't log a false orphan entry. Logged because
		// this branch also fires if baoWritten is ever lost (e.g. a
		// status-pruning CRD reapply) — silently releasing a grant kind
		// here would be a revocation that quietly didn't happen.
		l.Info("no bao object was ever confirmed for this CR; releasing finalizer without bao cleanup"+
			baoIdentitySuffix(obj), "finalizer", r.FinalizerName)
	case !obj.IsDeletable():
		// Bao-side cleanup disabled — orphan-by-design kind or
		// deletionPolicy=Retain. The CR is about to disappear; the log
		// and Event are the only traces of what was kept in bao.
		l.Info("bao-side cleanup disabled; releasing finalizer without removing bao object (intentional orphan)"+
			baoIdentitySuffix(obj), "finalizer", r.FinalizerName)
		r.event(obj, corev1.EventTypeNormal, "BaoObjectOrphaned",
			"CR deleted without bao-side cleanup"+baoIdentitySuffix(obj))
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

// setReadyAndMarkWritten patches Ready and, when markOwnership is
// true, flips status.baoWritten and records the bao identity.
// markOwnership is false only for a no-write pass of a primitive
// without a CheckCollision hook (see the ownership comment in
// Reconcile). Everything goes in one MergeFrom patch so a crash cannot
// leave Ready=True with baoWritten=false, nor baoWritten=true without
// the identity that rename cleanup needs. Marked no-write passes also
// backfill the identity onto CRs written before the field existed.
func (r *VaultResource[T]) setReadyAndMarkWritten(ctx context.Context, key client.ObjectKey, status metav1.ConditionStatus, reason, msg string, markOwnership bool, curName, curNS string, mutator StatusMutator[T]) error {
	err := r.patchStatusOnce(ctx, key, status, reason, msg, markOwnership, curName, curNS, mutator)
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
// maxEventMsgLen keeps Events readable in kubectl's table output. Not a
// platform limit; the condition keeps the full text.
const maxEventMsgLen = 512

func truncateForEvent(msg string) string {
	if len(msg) <= maxEventMsgLen {
		return msg
	}
	return msg[:maxEventMsgLen] + "… (full message in status.conditions)"
}

// emitReadyEvent records an Event when the Ready condition transitions. No-op
// when Recorder is nil.
//
// Gating on the transition is what bounds volume: patchStatusOnce runs on every
// reconcile, so an ungated emit would be one Event per CR per PeriodicInterval
// forever, and one per ErrorBackoff for a wedged CR. A first-ever success is
// deliberately silent — Ready=True and baoWritten latch permanently, so an
// Event would duplicate durable state. A recovery is not, because the patch
// writing Ready=True erases the message explaining the failure.
func (r *VaultResource[T]) emitReadyEvent(obj T, hadPrev bool, prevStatus metav1.ConditionStatus,
	prevReason string, status metav1.ConditionStatus, reason, msg string) {
	if r.Recorder == nil {
		return
	}
	switch {
	case status == metav1.ConditionFalse &&
		(!hadPrev || prevStatus != metav1.ConditionFalse || prevReason != reason):
		// Reason, not message: messages carry varying detail (serials, bao
		// bodies) and comparing them would defeat the gate.
		r.Recorder.Event(obj, corev1.EventTypeWarning, reason, truncateForEvent(msg))
	case status == metav1.ConditionTrue && hadPrev && prevStatus == metav1.ConditionFalse:
		r.Recorder.Event(obj, corev1.EventTypeNormal, ReasonReconciled, "bao object converged")
	}
}

// baoIdentitySuffix renders the CR's bao-side identity for appending to a
// failure message. Root is named explicitly so a message never reads
// `openbao namespace ""`.
func baoIdentitySuffix(obj VaultCR) string {
	if ns := obj.OpenBaoNamespace(); ns != "" {
		return fmt.Sprintf(" [bao object %q, openbao namespace %q]", obj.BaoName(), ns)
	}
	return fmt.Sprintf(" [bao object %q, openbao root namespace]", obj.BaoName())
}

func (r *VaultResource[T]) patchStatusOnce(ctx context.Context, key client.ObjectKey, status metav1.ConditionStatus, reason, msg string, markWritten bool, curName, curNS string, mutator StatusMutator[T]) error {
	// Hoisted for the Event: the prior condition is only visible inside the
	// closure, but the Event must be emitted after the patch succeeds. Each
	// attempt overwrites, so a conflict retry reports what actually landed.
	var (
		emitObj    T
		emitMsg    string
		hadPrev    bool
		prevStatus metav1.ConditionStatus
		prevReason string
	)

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cur := r.Handlers.NewInstance()
		if err := r.Get(ctx, key, cur); err != nil {
			return err
		}
		origObj, ok := cur.DeepCopyObject().(client.Object)
		if !ok {
			return fmt.Errorf("deep copy of %T is not a client.Object", cur)
		}

		// The openbao namespace travels as an X-Vault-Namespace header, so it
		// appears in no SDK error string. Composed here rather than per
		// callsite so a new primitive cannot omit it. New variable, not msg:
		// this closure re-runs on conflict and would append once per attempt.
		condMsg := msg
		if status == metav1.ConditionFalse {
			condMsg += baoIdentitySuffix(cur)
		}

		conds := cur.GetConditions()

		// Captured before SetStatusCondition overwrites it.
		if p := apimeta.FindStatusCondition(conds, ConditionReady); p != nil {
			hadPrev, prevStatus, prevReason = true, p.Status, p.Reason
		} else {
			hadPrev = false
		}
		emitObj, emitMsg = cur, condMsg

		// Derive the Synced/Progressing companions from the same reconcile
		// outcome so all three stay consistent in one patch. A non-fatal
		// intermediate reason (awaiting external signature) keeps Synced=True
		// (the object was advanced/CSR exported) but marks Progressing=True;
		// any other Ready=False is a real failure -> Synced=False, not
		// progressing (stuck). Ready=True -> fully converged.
		const awaiting = ReasonAwaitingExternalSignature
		progressing := status != metav1.ConditionTrue && reason == awaiting
		synced := metav1.ConditionTrue
		if status != metav1.ConditionTrue && !progressing {
			synced = metav1.ConditionFalse
		}
		progressingStatus := metav1.ConditionFalse
		if progressing {
			progressingStatus = metav1.ConditionTrue
		}

		apimeta.SetStatusCondition(&conds, metav1.Condition{
			Type:               ConditionReady,
			Status:             status,
			Reason:             reason,
			Message:            condMsg,
			ObservedGeneration: cur.GetGeneration(),
		})
		apimeta.SetStatusCondition(&conds, metav1.Condition{
			Type:               ConditionSynced,
			Status:             synced,
			Reason:             reason,
			Message:            condMsg,
			ObservedGeneration: cur.GetGeneration(),
		})
		apimeta.SetStatusCondition(&conds, metav1.Condition{
			Type:               ConditionProgressing,
			Status:             progressingStatus,
			Reason:             reason,
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
	if err != nil {
		// No Event on a failed write: one announcing a recovery that was never
		// persisted would outlive the condition as a lie.
		return err
	}

	// Emitted outside the retry closure so a conflict retry cannot fire
	// duplicate Events for a single transition.
	r.emitReadyEvent(emitObj, hadPrev, prevStatus, prevReason, status, reason, emitMsg)
	return nil
}
