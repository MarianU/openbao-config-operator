package openbaopolicy

import (
	"context"
	"errors"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaopolicies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaopolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaopolicies/finalizers,verbs=update

// OpenBaoPolicyFinalizer follows the Kubernetes convention
// <resource>.<group>/finalizer.
const OpenBaoPolicyFinalizer = "openbaopolicy.security.mto.stakater.com/finalizer"

type OpenBaoPolicyReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoPolicy]
}

// NewOpenBaoPolicyReconcilerWithClient is the test-friendly constructor.
func NewOpenBaoPolicyReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoPolicyReconciler {
	return &OpenBaoPolicyReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoPolicy](mgr, OpenBaoPolicyFinalizer,
			OpenBaoPolicyHandlers(mgr.GetClient(), bao)),
	}
}

// OpenBaoPolicyHandlers builds the bao-I/O callbacks. Exposed so tests can
// wire them into a hand-constructed VaultResource without a manager. Every
// bao call carries spec.openbaoNamespace as the X-Vault-Namespace header
// via baoclient.WithNamespace; empty (the default) targets root.
func OpenBaoPolicyHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoPolicy] {
	return resource.Handlers[*v1alpha1.OpenBaoPolicy]{
		NewInstance: func() *v1alpha1.OpenBaoPolicy { return &v1alpha1.OpenBaoPolicy{} },
		BaoGet: func(ctx context.Context, p *v1alpha1.OpenBaoPolicy) (map[string]any, error) {
			body, err := bao.GetPolicy(ctx, p.BaoName(), baoclient.WithNamespace(p.OpenBaoNamespace()))
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{"policy": body}, nil
		},
		BaoWrite: func(ctx context.Context, p *v1alpha1.OpenBaoPolicy) (resource.StatusMutator[*v1alpha1.OpenBaoPolicy], error) {
			if err := checkPolicyNameCollision(ctx, cl, p); err != nil {
				return nil, err
			}
			return nil, bao.UpsertPolicy(ctx, p.BaoName(), p.Spec.Policy, baoclient.WithNamespace(p.OpenBaoNamespace()))
		},
		BaoDelete: func(ctx context.Context, p *v1alpha1.OpenBaoPolicy) error {
			return bao.DeletePolicy(ctx, p.BaoName(), baoclient.WithNamespace(p.OpenBaoNamespace()))
		},
		BaoDeleteIdentity: func(ctx context.Context, _ *v1alpha1.OpenBaoPolicy, name, namespace string) error {
			return bao.DeletePolicy(ctx, name, baoclient.WithNamespace(namespace))
		},
		CheckCollision: func(ctx context.Context, p *v1alpha1.OpenBaoPolicy) error {
			return checkPolicyNameCollision(ctx, cl, p)
		},
	}
}

// checkPolicyNameCollision returns ErrNameCollision when another OpenBaoPolicy
// CR (different UID) already targets the same (bao policy name, OpenBao
// namespace) tuple. Two CRs targeting the same name in different bao
// namespaces are not a collision — bao stores them as separate objects.
//
// Tie-breaking: older CreationTimestamp wins; on exact tie, lexicographic
// order of <namespace>/<name> wins. This guarantees both colliding CRs
// converge to the same outcome — exactly one writes, the other surfaces a
// clear status condition — even if reconciles run concurrently before
// status from one has propagated to the other.
//
// Without this guard, two OpenBaoPolicy CRs in different k8s namespaces
// sharing metadata.name (or spec.name) and pointing at the same bao
// namespace silently overwrite each other's bao body on every reconcile,
// and a delete of one removes the bao object the other thinks it owns.
func checkPolicyNameCollision(ctx context.Context, cl client.Client, p *v1alpha1.OpenBaoPolicy) error {
	var all v1alpha1.OpenBaoPolicyList
	if err := cl.List(ctx, &all); err != nil {
		// If we can't list, fail closed — better to surface a transient
		// error than to silently overwrite. Tag with ErrInternal so the
		// status surfaces ReasonInternalError; the fault is the k8s
		// apiserver, not bao, and reason=BaoError would mislead an
		// on-call paging on this condition.
		return fmt.Errorf("%w: listing openbaopolicies for collision check: %v",
			resource.ErrInternal, err)
	}
	targetName := p.BaoName()
	targetNS := p.OpenBaoNamespace()
	mineKey := p.Namespace + "/" + p.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == p.UID {
			continue
		}
		if other.BaoName() != targetName {
			continue
		}
		if other.OpenBaoNamespace() != targetNS {
			// Same bao name in a different OpenBao namespace is not a
			// collision — bao isolates them via X-Vault-Namespace, so
			// each CR owns a distinct bao object.
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
			return fmt.Errorf("%w: bao policy %q in namespace %q already owned by OpenBaoPolicy %s/%s",
				resource.ErrNameCollision, targetName, targetNS, other.Namespace, other.Name)
		}
	}
	return nil
}

// SetupWithManager registers the controller with a GenerationChangedPredicate
// so status writes do not trigger re-reconciles.
func (r *OpenBaoPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoPolicy{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
