// +kubebuilder:rbac:groups=tenantoperator.stakater.com,resources=tenants,verbs=get;list;watch
// +kubebuilder:rbac:groups=tenantoperator.stakater.com,resources=tenants/status,verbs=get
package tenant

import (
	"context"
	"fmt"
	"os"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	mto "github.com/stakater-ab/tenant-operator/api/v1beta3"

	// internal utils
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	bao "github.com/stakater-ab/mto-extension-openbao/internal/utils"
)

type TenantReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Log       logr.Logger
	baoClient baoclient.Client

	kvMount   string // e.g., "secret"
	authMount string // e.g., "kubernetes"
	env       string // e.g., "prod"
}

func NewTenantReconciler(mgr ctrl.Manager) (*TenantReconciler, error) {
	addr, ok := os.LookupEnv("VAULT_ADDR")
	if !ok || addr == "" {
		addr = os.Getenv("BAO_ADDR")
	}
	token, ok := os.LookupEnv("VAULT_TOKEN")
	if !ok || token == "" {
		token = os.Getenv("BAO_TOKEN")
	}
	if addr == "" || token == "" {
		return nil, fmt.Errorf("set VAULT_ADDR/VAULT_TOKEN (or BAO_ADDR/BAO_TOKEN)")
	}

	if addr == "" || token == "" {
		return nil, fmt.Errorf("BAO_ADDR/BAO_TOKEN must be set")
	}
	return &TenantReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Log:       ctrl.Log.WithName("controller").WithName("Tenant"),
		baoClient: baoclient.NewHTTPClient(addr, token),
		kvMount:   "secret",
		authMount: "kubernetes",
		env:       "prod",
	}, nil
}

func (r *TenantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("tenant", req.Name)

	var t mto.Tenant
	if err := r.Get(ctx, req.NamespacedName, &t); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	ten := t.GetName()

	ok, err := r.baoClient.CheckKVv2Mount(ctx, r.kvMount)
	if err != nil {
		log.Error(err, "bao mount check failed", "mount", r.kvMount)
		return ctrl.Result{}, err
	}
	if !ok {
		err := fmt.Errorf("kv-v2 mount %q not present or not v2", r.kvMount)
		log.Error(err, "precondition failed")
		return ctrl.Result{}, err
	}

	type nsEntry struct {
		short      string
		withPrefix bool
	}
	var wanted []nsEntry
	if t.Spec.Namespaces != nil {
		for _, s := range t.Spec.Namespaces.WithTenantPrefix {
			wanted = append(wanted, nsEntry{short: string(s), withPrefix: true})
		}
		for _, s := range t.Spec.Namespaces.WithoutTenantPrefix {
			wanted = append(wanted, nsEntry{short: string(s), withPrefix: false})
		}
	}
	if len(wanted) == 0 {
		return ctrl.Result{}, nil
	}

	okAuth, err := r.baoClient.CheckAuthMount(ctx, r.authMount)
	if err != nil {
		log.Error(err, "bao auth-mount check failed", "authMount", r.authMount)
		return ctrl.Result{}, err
	}
	if !okAuth {
		return ctrl.Result{}, fmt.Errorf("kubernetes auth mount %q not found or wrong type; enable it or set OPENBAO_AUTH_MOUNT", r.authMount)
	}

	for _, it := range wanted {
		nsFull := bao.NamespaceFull(ten, it.short, it.withPrefix)
		polName := bao.PolicyNameEditor(ten, nsFull)
		roleName := bao.RoleName(ten, nsFull)
		polBody := bao.KVv2NamespaceEditorPolicy(r.kvMount, ten, r.env, nsFull)

		if err := r.baoClient.UpsertPolicy(ctx, polName, polBody); err != nil {
			log.Error(err, "failed to upsert policy", "policy", polName)
			return ctrl.Result{}, err
		}

		renew := true
		spec := baoclient.K8sRoleSpec{
			Policies:                      []string{polName},
			BoundServiceAccountNames:      []string{"default"},
			BoundServiceAccountNamespaces: []string{nsFull},
			TokenTTL:                      "1h",
			TokenMaxTTL:                   "4h",
			Renewable:                     &renew,
		}
		if err := r.baoClient.UpsertK8sRole(ctx, r.authMount, roleName, spec); err != nil {
			log.Error(err, "failed to upsert k8s auth role", "role", roleName)
			return ctrl.Result{}, err
		}

		log.Info("ensured tenant namespace artifacts", "nsFull", nsFull, "policy", polName, "role", roleName)
	}

	return ctrl.Result{}, nil
}

func (r *TenantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mto.Tenant{}).
		Complete(r)
}
