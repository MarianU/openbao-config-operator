package openbaoconnection

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8srec "k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
	"github.com/stakater/openbao-config-operator/internal/connection"
	"github.com/stakater/openbao-config-operator/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoconnections,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoconnections/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// RequeuePeriod is how often a healthy connection is re-probed so the auth
// token (and any spec drift) stays current.
const RequeuePeriod = 5 * time.Minute

// OpenBaoConnectionReconciler validates and health-checks OpenBaoConnection
// CRs. It is the controller that uses the connection resolver directly (to
// prove its own connection), rather than via a primitive's reference.
type OpenBaoConnectionReconciler struct {
	client.Client
	// Recorder emits Events on status transitions. Optional; nil skips.
	Recorder k8srec.EventRecorder
}

// NewReconciler constructs the connection reconciler.
func NewReconciler(cl client.Client) *OpenBaoConnectionReconciler {
	return &OpenBaoConnectionReconciler{Client: cl}
}

func (r *OpenBaoConnectionReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx).WithValues("name", req.Name, "namespace", req.Namespace)

	c := &v1alpha1.OpenBaoConnection{}
	if err := r.Get(ctx, req.NamespacedName, c); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// No finalizer needed: an OpenBaoConnection owns no bao object, so a
	// delete has nothing to tear down.
	if !c.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	if ok, err := c.IsValid(); !ok {
		l.Info("invalid connection", "error", err)
		r.writeStatus(ctx, c, false, resource.ReasonInvalid, err.Error(), 0)
		return ctrl.Result{}, nil
	}

	bao, err := connection.BuildClient(ctx, r.Client, c)
	if err != nil {
		// Connection definition problem (missing secret, bad cert) — stable
		// until the user fixes the connection.
		l.Info("connection build failed", "error", err)
		r.writeStatus(ctx, c, false, resource.ReasonConnectionError, err.Error(), 0)
		return ctrl.Result{}, nil
	}

	info, err := bao.TokenLookupSelf(ctx)
	if err != nil {
		// Reachability / auth problem — OpenBao unreachable or denies the
		// token. Requeue so it recovers when it heals.
		l.Error(err, "connection probe failed")
		r.writeStatus(ctx, c, false, resource.ReasonBaoError, err.Error(), 0)
		return ctrl.Result{Requeue: true}, nil
	}

	r.writeStatus(ctx, c, true, resource.ReasonReconciled, "connection OK", info.TTLSeconds)
	return ctrl.Result{RequeueAfter: RequeuePeriod}, nil
}

// SetupWithManager registers the controller, watching both the connection CR
// and any referenced Secrets so a token/CA/client-cert rotation re-probes
// immediately.
func (r *OpenBaoConnectionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoConnection{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.connectionsReferencingSecret)).
		Complete(r)
}

// connectionsReferencingSecret maps a Secret to the OpenBaoConnections (same
// namespace) that reference it — as CA / client cert / token source — so a
// value rotation triggers an immediate re-probe.
func (r *OpenBaoConnectionReconciler) connectionsReferencingSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	sec, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}
	var list v1alpha1.OpenBaoConnectionList
	if err := r.List(ctx, &list, client.InNamespace(sec.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		if references(&list.Items[i], sec.Name) {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: list.Items[i].Namespace, Name: list.Items[i].Name},
			})
		}
	}
	return reqs
}

func references(c *v1alpha1.OpenBaoConnection, secretName string) bool {
	s := c.Spec.TLS
	if s.CACertSecretRef != nil && s.CACertSecretRef.Name == secretName {
		return true
	}
	if s.ClientCertSecretRef != nil && s.ClientCertSecretRef.Name == secretName {
		return true
	}
	if c.Spec.Auth.Token != nil && c.Spec.Auth.Token.TokenSecretRef.Name == secretName {
		return true
	}
	return false
}

// writeStatus patches the OpenBaoConnection status: a single Ready condition
// (replace by type) plus Authenticated / TokenTTLSeconds / ObservedGeneration.
func (r *OpenBaoConnectionReconciler) writeStatus(ctx context.Context, c *v1alpha1.OpenBaoConnection, ok bool, reason, msg string, ttl int64) {
	if r.Recorder != nil {
		r.Recorder.Event(c, "Normal", reason, msg)
	}
	cur := &v1alpha1.OpenBaoConnection{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: c.Name}, cur); err != nil {
		return
	}
	st := metav1.ConditionFalse
	if ok {
		st = metav1.ConditionTrue
	}
	ready := metav1.Condition{
		Type:               resource.ConditionReady,
		Status:             st,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: cur.Generation,
	}
	conds := []metav1.Condition{ready}
	for _, existing := range cur.Status.Conditions {
		if existing.Type != resource.ConditionReady {
			conds = append(conds, existing)
		}
	}
	cur.Status.Conditions = conds
	cur.Status.ObservedGeneration = cur.Generation
	cur.Status.Authenticated = ok
	cur.Status.TokenTTLSeconds = ttl
	if err := r.Status().Update(ctx, cur); err != nil {
		// Best-effort status write.
		return
	}
}
