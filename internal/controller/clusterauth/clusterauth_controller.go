package clusterauth

import (
	"context"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

const (
	authCheckErrorBackoff = 30 * time.Second
	authCheckInterval     = 5 * time.Minute
)

func (r *ClusterAuthReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx).WithValues("openbaoextension", req.NamespacedName)

	var obx extv1alpha1.OpenBaoExtension
	if err := r.Get(ctx, req.NamespacedName, &obx); err != nil {
		// deleted or not found; nothing to do
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	l.Info("reconciling OpenBaoExtension", "ns", req.Namespace, "name", req.Name)

	// Default: pessimistic until proven OK
	r.setCondGen(&obx, metav1.ConditionUnknown, extv1alpha1.ReasonReconciling, "Reconciling")
	utils.RecomputeReadyInPlace(&obx)
	_ = r.patchStatus(ctx, &obx)

	// Validate config
	if obx.Spec.Server.URL == "" ||
		obx.Spec.Server.TokenSecretRef.Name == "" ||
		obx.Spec.Server.TokenSecretRef.Key == "" {
		r.setCondGen(&obx, metav1.ConditionFalse, extv1alpha1.ReasonError,
			"spec.server.url and tokenSecretRef{name,key} are required")
		utils.RecomputeReadyInPlace(&obx)
		_ = r.patchStatus(ctx, &obx)
		return ctrl.Result{}, nil
	}

	// Read token from Secret
	var sec corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: req.Namespace,
		Name:      obx.Spec.Server.TokenSecretRef.Name,
	}, &sec); err != nil {
		r.setCondGen(&obx, metav1.ConditionFalse, extv1alpha1.ReasonError, err.Error())
		utils.RecomputeReadyInPlace(&obx)
		_ = r.patchStatus(ctx, &obx)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	raw, ok := sec.Data[obx.Spec.Server.TokenSecretRef.Key]
	if !ok || len(raw) == 0 {
		r.setCondGen(&obx, metav1.ConditionFalse, extv1alpha1.ReasonError, "secret key empty or missing")
		utils.RecomputeReadyInPlace(&obx)
		_ = r.patchStatus(ctx, &obx)
		return ctrl.Result{}, nil
	}
	token := string(raw)
	baseURL := strings.TrimRight(obx.Spec.Server.URL, "/")

	r.removeCondGen(&obx)
	utils.RecomputeReadyInPlace(&obx)
	_ = r.patchStatus(ctx, &obx)

	// Use baoclient (no ad-hoc HTTP here)
	cli := baoclient.NewHTTPClient(baseURL, token)

	okMount, err := cli.CheckAuthMount(ctx, constants.DefaultAuthMount)
	if err != nil {
		l.Error(err, "bao sys/auth check failed")
		r.setCondGen(&obx, metav1.ConditionFalse, extv1alpha1.ReasonError, err.Error())
		utils.RecomputeReadyInPlace(&obx)
		_ = r.patchStatus(ctx, &obx)
		// back off a bit
		return ctrl.Result{RequeueAfter: authCheckErrorBackoff}, nil
	}

	if okMount {
		r.removeCondGen(&obx)
		r.setCondGen(&obx, metav1.ConditionTrue, extv1alpha1.ReasonSuccess, "auth/"+constants.DefaultAuthMount+" mount detected")
	} else {
		r.setCondGen(&obx, metav1.ConditionFalse, extv1alpha1.ReasonWaitingDependencies, "auth/"+constants.DefaultAuthMount+" not mounted")
	}
	utils.RecomputeReadyInPlace(&obx)

	if err := r.patchStatus(ctx, &obx); err != nil {
		return ctrl.Result{}, err
	}

	// Recheck periodically
	return ctrl.Result{RequeueAfter: authCheckInterval}, nil
}

// setCondGen wraps utils.SetCond for AuthConfigured and stamps ObservedGeneration (tests assert this).
func (r *ClusterAuthReconciler) setCondGen(obx *extv1alpha1.OpenBaoExtension, st metav1.ConditionStatus, reason, msg string) {
	const typ = extv1alpha1.CondAuthConfigured
	utils.SetCond(&obx.Status.Conditions, typ, st, reason, msg)
	if c := utils.FindCond(obx.Status.Conditions, typ); c != nil {
		c.ObservedGeneration = obx.GetGeneration()
	}
}

// remove condition entries of AuthConfigured type to avoid stale failures persisting
func (r *ClusterAuthReconciler) removeCondGen(obx *extv1alpha1.OpenBaoExtension) {
	const typ = extv1alpha1.CondAuthConfigured
	conds := obx.Status.Conditions
	out := conds[:0]
	for i := range conds {
		if conds[i].Type != typ {
			out = append(out, conds[i])
		}
	}
	obx.Status.Conditions = out
}

func (r *ClusterAuthReconciler) patchStatus(ctx context.Context, obx *extv1alpha1.OpenBaoExtension) error {
	// conservative: Update() on the status subresource (your RBAC already allows it)
	return r.Status().Update(ctx, obx)
}

// SetupWithManager registers the controller.
func (r *ClusterAuthReconciler) SetupWithManager(mgr ctrl.Manager) error {
	mapSecret := func(ctx context.Context, obj client.Object) []reconcile.Request {
		sec, ok := obj.(*corev1.Secret)
		if !ok {
			return nil
		}
		var list extv1alpha1.OpenBaoExtensionList
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
		For(&extv1alpha1.OpenBaoExtension{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(mapSecret)).
		Complete(r)
}
