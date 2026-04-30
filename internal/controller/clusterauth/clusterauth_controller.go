package clusterauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	extv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/constants"
	"github.com/stakater-ab/mto-extension-openbao/internal/utils"
)

// -------- RBAC --------

//+kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoextensions,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoextensions/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoextensions/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

type ClusterAuthReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func NewClusterAuthReconciler(mgr ctrl.Manager) *ClusterAuthReconciler {
	return &ClusterAuthReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}
}

const (
	authCheckErrorBackoff = 30 * time.Second
	authCheckInterval     = 5 * time.Minute
)

func (r *ClusterAuthReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx).WithValues("openbaoextension", req.NamespacedName)

	var obx extv1alpha1.OpenBaoExtension
	if err := r.Get(ctx, req.NamespacedName, &obx); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	l.Info("reconciling OpenBaoExtension", "ns", req.Namespace, "name", req.Name)

	// Validate minimal spec early
	if obx.Spec.Server.URL == "" ||
		obx.Spec.Server.TokenSecretRef.Name == "" ||
		obx.Spec.Server.TokenSecretRef.Key == "" {
		_ = r.setAuthCond(ctx, req.NamespacedName, metav1.ConditionFalse, extv1alpha1.ReasonError,
			"spec.server.url and tokenSecretRef{name,key} are required")
		return ctrl.Result{}, nil
	}

	// Read token from Secret
	var sec corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: req.Namespace,
		Name:      obx.Spec.Server.TokenSecretRef.Name,
	}, &sec); err != nil {
		_ = r.setAuthCond(ctx, req.NamespacedName, metav1.ConditionFalse, extv1alpha1.ReasonError, err.Error())
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	raw, ok := sec.Data[obx.Spec.Server.TokenSecretRef.Key]
	if !ok || len(raw) == 0 {
		_ = r.setAuthCond(ctx, req.NamespacedName, metav1.ConditionFalse, extv1alpha1.ReasonError, "secret key empty or missing")
		return ctrl.Result{}, nil
	}

	token := string(raw)
	baseURL := strings.TrimRight(obx.Spec.Server.URL, "/")
	cli, err := baoclient.NewHTTPClient(baseURL, token)
	if err != nil {
		_ = r.setAuthCond(ctx, req.NamespacedName, metav1.ConditionFalse, extv1alpha1.ReasonError, err.Error())
		return ctrl.Result{RequeueAfter: authCheckErrorBackoff}, nil
	}

	// Check mount
	okMount, err := cli.CheckAuthMount(ctx, constants.DefaultAuthMount)
	if err != nil {
		l.Error(err, "bao sys/auth check failed")
		_ = r.setAuthCond(ctx, req.NamespacedName, metav1.ConditionFalse, extv1alpha1.ReasonError, err.Error())
		return ctrl.Result{RequeueAfter: authCheckErrorBackoff}, nil
	}

	// Enable if missing
	if !okMount {
		l.Info("auth mount missing; enabling", "mount", constants.DefaultAuthMount, "type", "kubernetes")
		if err := cli.EnableAuthMount(ctx, constants.DefaultAuthMount, "kubernetes"); err != nil {
			l.Error(err, "failed to enable kubernetes auth", "mount", constants.DefaultAuthMount)
			msg := err.Error()
			if isForbidden(err) {
				msg = "permission denied enabling auth mount; token needs capabilities on sys/auth/* (create, update, read, sudo)"
			}
			_ = r.setAuthCond(ctx, req.NamespacedName, metav1.ConditionFalse, extv1alpha1.ReasonWaitingDependencies, msg)
			return ctrl.Result{RequeueAfter: authCheckErrorBackoff}, nil
		}
		// Re-check
		ok, err := cli.CheckAuthMount(ctx, constants.DefaultAuthMount)
		if err != nil {
			l.Error(err, "bao sys/auth re-check failed after enable")
			_ = r.setAuthCond(ctx, req.NamespacedName, metav1.ConditionFalse, extv1alpha1.ReasonError, err.Error())
			return ctrl.Result{RequeueAfter: authCheckErrorBackoff}, nil
		}
		okMount = ok
	}

	// Final condition update (single write)
	if okMount {
		_ = r.setAuthCond(ctx, req.NamespacedName, metav1.ConditionTrue, extv1alpha1.ReasonSuccess,
			"auth/"+constants.DefaultAuthMount+" mount present")
	} else {
		_ = r.setAuthCond(ctx, req.NamespacedName, metav1.ConditionFalse, extv1alpha1.ReasonWaitingDependencies,
			"auth/"+constants.DefaultAuthMount+" not mounted")
	}

	// keep self-healing
	return ctrl.Result{RequeueAfter: authCheckInterval}, nil
}

// setAuthCond updates only the status.conditions with conflict-safe patching.
// It re-fetches the latest object, mutates, and patches status with MergeFrom.
// Ready is recomputed in-place via your utils helper.
func (r *ClusterAuthReconciler) setAuthCond(
	ctx context.Context,
	key types.NamespacedName,
	status metav1.ConditionStatus,
	reason, msg string,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var cur extv1alpha1.OpenBaoExtension
		if err := r.Get(ctx, key, &cur); err != nil {
			return err
		}
		orig := cur.DeepCopy()

		// Mutate condition
		utils.SetCondGen(&cur, extv1alpha1.CondAuthConfigured, status, reason, msg)
		utils.RecomputeReadyInPlace(&cur)

		// Patch only status
		return r.Status().Patch(ctx, &cur, client.MergeFrom(orig))
	})
}

// SetupWithManager registers the controller.
func (r *ClusterAuthReconciler) SetupWithManager(mgr ctrl.Manager) error {
	mapSecret := func(ctx context.Context, obj client.Object) []reconcile.Request {
		sec, ok := obj.(*corev1.Secret)
		if !ok {
			return nil
		}
		var list extv1alpha1.OpenBaoExtensionList
		if err := r.Client.List(ctx, &list, client.InNamespace(sec.Namespace)); err != nil {
			// Returning nil drops this Secret event; without a log, a
			// transient List failure silently delays drift detection
			// until the next 5m periodic. Log so it's debuggable.
			log.FromContext(ctx).Error(err, "mapSecret: list OpenBaoExtension failed; Secret event dropped",
				"secret", sec.Namespace+"/"+sec.Name)
			return nil
		}
		reqs := make([]reconcile.Request, 0, len(list.Items))
		for i := range list.Items {
			obx := &list.Items[i]
			if obx.Spec.Server.TokenSecretRef.Name == sec.Name {
				reqs = append(reqs, reconcile.Request{
					NamespacedName: types.NamespacedName{Namespace: obx.Namespace, Name: obx.Name},
				})
			}
		}
		return reqs
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&extv1alpha1.OpenBaoExtension{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(mapSecret)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

// --- helpers ---

// isForbidden returns true when err carries an HTTP 403 from bao,
// regardless of the surrounding error chain. Routes through
// baoclient's structured *StatusError via errors.As — substring
// matching on the error message is brittle (bao's wording changes
// across versions, and locale-aware tooling can re-render the body),
// and CLAUDE.md requires status classification through the typed
// error.
func isForbidden(err error) bool {
	if err == nil {
		return false
	}
	var se *baoclient.StatusError
	if errors.As(err, &se) {
		return se.StatusCode == http.StatusForbidden
	}
	return false
}
