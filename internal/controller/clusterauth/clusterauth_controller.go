package clusterauth

import (
	"context"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	obxv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
)

// -------- RBAC --------

//+kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoextensions,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoextensions/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoextensions/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

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

func (r *ClusterAuthReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx).WithValues("openbaoextension", req.NamespacedName)

	var obx obxv1alpha1.OpenBaoExtension
	if err := r.Get(ctx, req.NamespacedName, &obx); err != nil {
		// deleted or not found; nothing to do
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	l.Info("reconciling OpenBaoExtension", "ns", req.Namespace, "name", req.Name)

	// Default: pessimistic until proven OK
	setAuthCond(&obx, metav1.ConditionFalse, "Unknown", "Reconciling")

	// Validate config
	if obx.Spec.Server.URL == "" ||
		obx.Spec.Server.TokenSecretRef.Name == "" ||
		obx.Spec.Server.TokenSecretRef.Key == "" {
		setAuthCond(&obx, metav1.ConditionFalse, "MissingConfig",
			"spec.server.url and tokenSecretRef{name,key} are required")
		_ = r.patchStatus(ctx, &obx)
		return ctrl.Result{}, nil
	}

	// Read token from Secret
	var sec corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: req.Namespace,
		Name:      obx.Spec.Server.TokenSecretRef.Name,
	}, &sec); err != nil {
		setAuthCond(&obx, metav1.ConditionFalse, "TokenSecretMissing", err.Error())
		_ = r.patchStatus(ctx, &obx)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	raw, ok := sec.Data[obx.Spec.Server.TokenSecretRef.Key]
	if !ok || len(raw) == 0 {
		setAuthCond(&obx, metav1.ConditionFalse, "TokenKeyMissing", "secret key empty or missing")
		_ = r.patchStatus(ctx, &obx)
		return ctrl.Result{}, nil
	}
	token := string(raw)
	baseURL := strings.TrimRight(obx.Spec.Server.URL, "/")

	// Use baoclient (no ad-hoc HTTP here)
	cli := baoclient.NewHTTPClient(baseURL, token)

	okMount, err := cli.CheckAuthMount(ctx, "kubernetes")
	if err != nil {
		l.Error(err, "bao sys/auth check failed")
		setAuthCond(&obx, metav1.ConditionFalse, "BaoError", err.Error())
		_ = r.patchStatus(ctx, &obx)
		// backoff a bit
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	if okMount {
		setAuthCond(&obx, metav1.ConditionTrue, "KubernetesAuthPresent", "auth/kubernetes mount detected")
	} else {
		setAuthCond(&obx, metav1.ConditionFalse, "KubernetesAuthMissing", "auth/kubernetes not mounted")
	}

	if err := r.patchStatus(ctx, &obx); err != nil {
		return ctrl.Result{}, err
	}

	// Recheck periodically
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

func (r *ClusterAuthReconciler) patchStatus(ctx context.Context, obx *obxv1alpha1.OpenBaoExtension) error {
	return r.Status().Update(ctx, obx)
}

func setAuthCond(obx *obxv1alpha1.OpenBaoExtension, status metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(&obx.Status.Conditions, metav1.Condition{
		Type:               "AuthConfigured",
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: obx.GetGeneration(),
		LastTransitionTime: metav1.Now(),
	})
}

// SetupWithManager registers the controller.
func (r *ClusterAuthReconciler) SetupWithManager(mgr ctrl.Manager) error {
	mapSecret := func(ctx context.Context, obj client.Object) []reconcile.Request {
		sec, ok := obj.(*corev1.Secret)
		if !ok {
			return nil
		}
		var list obxv1alpha1.OpenBaoExtensionList
		// list only OBX in the Secret's namespace
		if err := r.Client.List(ctx, &list, client.InNamespace(sec.Namespace)); err != nil {
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
		For(&obxv1alpha1.OpenBaoExtension{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(mapSecret)).
		Complete(r)
}
