package vco

import (
	"context"
	"fmt"
	"os"
	"strings"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	vcov1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/vco/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=policies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=policies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=policies/finalizers,verbs=update

// PolicyFinalizer follows the Kubernetes convention <resource>.<group>/finalizer.
const PolicyFinalizer = "policy.security.mto.stakater.com/finalizer"

// PolicyReconciler reconciles a Policy CR. All lifecycle logic lives in the
// shared VaultResource base; this wrapper only provides the primitive-specific
// bao I/O and the SetupWithManager invocation with the concrete For() type.
type PolicyReconciler struct {
	*resource.VaultResource[*vcov1alpha1.Policy]
}

// NewPolicyReconciler constructs the reconciler. The bao client is read from
// VAULT_ADDR / VAULT_TOKEN (or BAO_ADDR / BAO_TOKEN) at construction time,
// matching the Tenant controller's pattern at
// internal/controller/tenant/tenant_controller.go:NewTenantReconciler.
func NewPolicyReconciler(mgr ctrl.Manager) (*PolicyReconciler, error) {
	bao, err := newBaoFromEnv()
	if err != nil {
		return nil, err
	}
	return NewPolicyReconcilerWithClient(mgr, bao), nil
}

// NewPolicyReconcilerWithClient is the test-friendly constructor that accepts
// an explicit bao client rather than reading env.
func NewPolicyReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *PolicyReconciler {
	handlers := resource.Handlers[*vcov1alpha1.Policy]{
		NewInstance: func() *vcov1alpha1.Policy { return &vcov1alpha1.Policy{} },
		BaoGet: func(ctx context.Context, p *vcov1alpha1.Policy) (map[string]any, error) {
			body, err := bao.GetPolicy(ctx, p.BaoName())
			if err != nil {
				// Translate 404-ish bao errors into the sentinel the base recognises.
				lower := strings.ToLower(err.Error())
				if strings.Contains(lower, "404") || strings.Contains(lower, "not found") {
					return nil, resource.ErrBaoNotFound
				}
				return nil, err
			}
			if body == "" {
				return nil, resource.ErrBaoNotFound
			}
			return map[string]any{"policy": body}, nil
		},
		BaoWrite: func(ctx context.Context, p *vcov1alpha1.Policy) error {
			return bao.UpsertPolicy(ctx, p.BaoName(), p.Spec.Policy)
		},
		BaoDelete: func(ctx context.Context, p *vcov1alpha1.Policy) error {
			return bao.DeletePolicy(ctx, p.BaoName())
		},
	}
	return &PolicyReconciler{
		VaultResource: resource.New[*vcov1alpha1.Policy](mgr, PolicyFinalizer, handlers),
	}
}

// SetupWithManager registers the controller with a GenerationChangedPredicate
// so status writes do not trigger re-reconciles.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vcov1alpha1.Policy{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

// newBaoFromEnv mirrors the Tenant controller's startup logic.
func newBaoFromEnv() (baoclient.Client, error) {
	addr, ok := os.LookupEnv("VAULT_ADDR")
	if !ok || addr == "" {
		addr = os.Getenv("BAO_ADDR")
	}
	token, ok := os.LookupEnv("VAULT_TOKEN")
	if !ok || token == "" {
		token = os.Getenv("BAO_TOKEN")
	}
	if addr == "" || token == "" {
		return nil, fmt.Errorf("set VAULT_ADDR/VAULT_TOKEN (or BAO_ADDR/BAO_TOKEN) for PolicyReconciler")
	}
	return baoclient.NewHTTPClient(addr, token), nil
}
