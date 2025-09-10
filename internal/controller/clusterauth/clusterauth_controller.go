package clusterauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

	obxv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
)

// -------- RBAC --------

//+kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoextensions,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoextensions/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoextensions/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

type ClusterAuthReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	HTTP   *http.Client
}

func NewClusterAuthReconciler(mgr ctrl.Manager) *ClusterAuthReconciler {
	return &ClusterAuthReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		HTTP:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (r *ClusterAuthReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx).WithValues("openbaoextension", req.NamespacedName)

	var obi obxv1alpha1.OpenBaoExtension
	if err := r.Get(ctx, req.NamespacedName, &obi); err != nil {
		// deleted or not found; nothing to do
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	l.Info("reconciling OpenBaoExtension", "ns", req.Namespace, "name", req.Name)

	// Default: pessimistic until proven OK
	setAuthCond(&obi, metav1.ConditionFalse, "Unknown", "Reconciling")

	// Fetch Bao server details
	if obi.Spec.Server.URL == "" ||
		obi.Spec.Server.TokenSecretRef.Name == "" ||
		obi.Spec.Server.TokenSecretRef.Key == "" {
		setAuthCond(&obi, metav1.ConditionFalse, "MissingConfig",
			"spec.server.url and tokenSecretRef{name,key} are required")
		_ = r.patchStatus(ctx, &obi)
		return ctrl.Result{}, nil
	}

	// Read token from Secret
	var sec corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: obi.Spec.Server.TokenSecretRef.Name}, &sec); err != nil {
		setAuthCond(&obi, metav1.ConditionFalse, "TokenSecretMissing", err.Error())
		_ = r.patchStatus(ctx, &obi)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	token, ok := sec.Data[obi.Spec.Server.TokenSecretRef.Key]
	if !ok || len(token) == 0 {
		setAuthCond(&obi, metav1.ConditionFalse, "TokenKeyMissing", "secret key empty or missing")
		_ = r.patchStatus(ctx, &obi)
		return ctrl.Result{}, nil
	}

	// Ensure k8s auth is mounted (non-destructive: first version only observe)
	mounted, err := r.kubernetesAuthMounted(ctx, strings.TrimRight(obi.Spec.Server.URL, "/"), string(token))
	if err != nil {
		l.Error(err, "bao sys/auth check failed")
		setAuthCond(&obi, metav1.ConditionFalse, "BaoError", err.Error())
		_ = r.patchStatus(ctx, &obi)
		// backoff a bit
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	if mounted {
		setAuthCond(&obi, metav1.ConditionTrue, "KubernetesAuthPresent", "auth/kubernetes mount detected")
	} else {
		setAuthCond(&obi, metav1.ConditionFalse, "KubernetesAuthMissing", "auth/kubernetes not mounted")
	}

	if err := r.patchStatus(ctx, &obi); err != nil {
		return ctrl.Result{}, err
	}

	// Recheck periodically
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

func (r *ClusterAuthReconciler) patchStatus(ctx context.Context, obi *obxv1alpha1.OpenBaoExtension) error {
	return r.Status().Update(ctx, obi)
}

func setAuthCond(obi *obxv1alpha1.OpenBaoExtension, status metav1.ConditionStatus, reason, msg string) {
	condType := "AuthConfigured"
	now := metav1.Now()
	meta.SetStatusCondition(&obi.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		LastTransitionTime: now,
		ObservedGeneration: obi.GetGeneration(),
	})
}

// ---- tiny Bao call: GET /v1/sys/auth and look for "kubernetes/" key ----

func (r *ClusterAuthReconciler) kubernetesAuthMounted(ctx context.Context, baseURL, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/v1/sys/auth", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Accept", "application/json")

	res, err := r.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode >= 300 {
		// return a small, helpful snippet
		snippet, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return false, fmt.Errorf("sys/auth HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(snippet)))
	}

	// read once; try both schemas (wrapped first, then unwrapped)
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return false, err
	}

	type mount struct {
		Type string `json:"type"`
	}

	// 1) Wrapped: { "data": { ... } }
	var wrapped struct {
		Data map[string]mount `json:"data"`
	}
	if err := json.Unmarshal(body, &wrapped); err == nil && wrapped.Data != nil {
		for _, m := range wrapped.Data {
			if strings.EqualFold(m.Type, "kubernetes") {
				return true, nil
			}
		}
		return false, nil
	}

	// 2) Canonical unwrapped: top-level map
	var unwrapped map[string]mount
	if err := json.Unmarshal(body, &unwrapped); err == nil && len(unwrapped) > 0 {
		for _, m := range unwrapped {
			if strings.EqualFold(m.Type, "kubernetes") {
				return true, nil
			}
		}
		return false, nil
	}

	// unexpected shape
	snippet := string(body)
	if len(snippet) > 512 {
		snippet = snippet[:512] + "…"
	}
	return false, fmt.Errorf("sys/auth: unexpected response shape; body=%q", strings.TrimSpace(snippet))
}

// SetupWithManager registers the controller.
func (r *ClusterAuthReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&obxv1alpha1.OpenBaoExtension{}).
		Complete(r)
}
