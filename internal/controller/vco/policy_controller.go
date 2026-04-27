package vco

import (
	"context"
	"errors"
	"fmt"
	"os"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

type PolicyReconciler struct {
	*resource.VaultResource[*vcov1alpha1.Policy]
}

// NewPolicyReconciler constructs the reconciler. The bao address and token
// come from VAULT_ADDR / VAULT_TOKEN (or BAO_ADDR / BAO_TOKEN) at startup.
func NewPolicyReconciler(mgr ctrl.Manager) (*PolicyReconciler, error) {
	bao, err := newBaoFromEnv()
	if err != nil {
		return nil, err
	}
	return NewPolicyReconcilerWithClient(mgr, bao), nil
}

// NewPolicyReconcilerWithClient is the test-friendly constructor.
func NewPolicyReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *PolicyReconciler {
	return &PolicyReconciler{
		VaultResource: resource.New[*vcov1alpha1.Policy](mgr, PolicyFinalizer,
			PolicyHandlers(mgr.GetClient(), bao)),
	}
}

// PolicyHandlers builds the bao-I/O callbacks. Exposed so tests can wire
// them into a hand-constructed VaultResource without a manager.
func PolicyHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*vcov1alpha1.Policy] {
	return resource.Handlers[*vcov1alpha1.Policy]{
		NewInstance: func() *vcov1alpha1.Policy { return &vcov1alpha1.Policy{} },
		BaoGet: func(ctx context.Context, p *vcov1alpha1.Policy) (map[string]any, error) {
			body, err := bao.GetPolicy(ctx, p.BaoName())
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{"policy": body}, nil
		},
		BaoWrite: func(ctx context.Context, p *vcov1alpha1.Policy) error {
			if err := checkPolicyNameCollision(ctx, cl, p); err != nil {
				return err
			}
			return bao.UpsertPolicy(ctx, p.BaoName(), p.Spec.Policy)
		},
		BaoDelete: func(ctx context.Context, p *vcov1alpha1.Policy) error {
			return bao.DeletePolicy(ctx, p.BaoName())
		},
	}
}

// checkPolicyNameCollision returns ErrNameCollision when another Policy CR
// (different UID) already targets the same bao policy name. Tie-breaking
// rule: the older CreationTimestamp wins; on exact tie, lexicographic order
// of <namespace>/<name> wins. This guarantees both colliding CRs converge
// to the same outcome — exactly one writes, the other surfaces a clear
// status condition — even if reconciles run concurrently before status
// from one has propagated to the other.
//
// Without this guard, two Policy CRs in different k8s namespaces sharing
// metadata.name (or spec.name) silently overwrite each other's bao body on
// every reconcile, and a delete of one removes the bao object the other
// thinks it owns.
func checkPolicyNameCollision(ctx context.Context, cl client.Client, p *vcov1alpha1.Policy) error {
	var all vcov1alpha1.PolicyList
	if err := cl.List(ctx, &all); err != nil {
		// If we can't list, fail closed — better to surface a transient
		// error than to silently overwrite. Tag with ErrInternal so the
		// status surfaces ReasonInternalError; the fault is the k8s
		// apiserver, not bao, and reason=BaoError would mislead an
		// on-call paging on this condition.
		return fmt.Errorf("%w: listing policies for collision check: %v",
			resource.ErrInternal, err)
	}
	target := p.BaoName()
	mineKey := p.Namespace + "/" + p.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == p.UID {
			continue
		}
		if other.BaoName() != target {
			continue
		}
		// Same bao target. Older CreationTimestamp wins; on tie, lex order
		// of <namespace>/<name> wins. Avoid metav1.Time.Equal because the
		// fake client (and real apiserver under nanosecond precision drift)
		// can return false even for what should be the "same instant".
		var otherWins bool
		switch {
		case other.CreationTimestamp.Before(&p.CreationTimestamp):
			otherWins = true
		case p.CreationTimestamp.Before(&other.CreationTimestamp):
			otherWins = false
		default:
			otherKey := other.Namespace + "/" + other.Name
			otherWins = otherKey < mineKey
		}
		if otherWins {
			return fmt.Errorf("%w: bao policy %q already owned by Policy %s/%s",
				resource.ErrNameCollision, target, other.Namespace, other.Name)
		}
	}
	return nil
}

// SetupWithManager registers the controller with a GenerationChangedPredicate
// so status writes do not trigger re-reconciles.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vcov1alpha1.Policy{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

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
	return baoclient.NewHTTPClient(addr, token)
}
