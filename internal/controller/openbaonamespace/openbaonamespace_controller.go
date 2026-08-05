package openbaonamespace

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

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaonamespaces,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaonamespaces/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaonamespaces/finalizers,verbs=update

// OpenBaoNamespaceFinalizer follows the Kubernetes convention
// <resource>.<group>/finalizer.
const OpenBaoNamespaceFinalizer = "openbaonamespace.security.mto.stakater.com/finalizer"

type OpenBaoNamespaceReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoNamespace]
}

// NewOpenBaoNamespaceReconcilerWithClient is the test-friendly constructor.
func NewOpenBaoNamespaceReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoNamespaceReconciler {
	return &OpenBaoNamespaceReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoNamespace](mgr, OpenBaoNamespaceFinalizer,
			OpenBaoNamespaceHandlers(mgr.GetClient(), bao)),
	}
}

// OpenBaoNamespaceHandlers builds the bao-I/O callbacks. Every call
// carries spec.openbaoNamespace as the X-Vault-Namespace header for
// nested-namespace creation: creating "acme/sub" goes through
// CreateNamespace("sub", WithNamespace("acme/")) — bao writes to
// sys/namespaces/sub under the acme/ context.
//
// BaoDelete runs only when spec.deletionPolicy is Delete. Bao's
// namespace delete CASCADES: it removes the namespace together with
// everything inside it — mounts, auth methods, secrets, keys, child
// namespaces — rather than blocking on live children. With the
// default Retain policy the
// shared base never calls BaoDelete and the bao namespace is
// intentionally orphaned.
func OpenBaoNamespaceHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoNamespace] {
	return resource.Handlers[*v1alpha1.OpenBaoNamespace]{
		NewInstance: func() *v1alpha1.OpenBaoNamespace { return &v1alpha1.OpenBaoNamespace{} },
		BaoGet: func(ctx context.Context, n *v1alpha1.OpenBaoNamespace) (map[string]any, error) {
			ns, err := bao.GetNamespace(ctx, n.BaoName(), baoclient.WithNamespace(n.OpenBaoNamespace()))
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			// Return the same payload shape GetPayload() emits so the
			// drift comparator finds equivalence on a present namespace.
			// Bao's read echoes the trailing-slash form ("acme/"); we
			// normalize to the spec form for comparison.
			_ = ns
			return map[string]any{"name": n.BaoName()}, nil
		},
		BaoWrite: func(ctx context.Context, n *v1alpha1.OpenBaoNamespace) (resource.StatusMutator[*v1alpha1.OpenBaoNamespace], error) {
			if err := checkNamespaceCollision(ctx, cl, n); err != nil {
				return nil, err
			}
			return nil, bao.CreateNamespace(ctx, n.BaoName(), baoclient.WithNamespace(n.OpenBaoNamespace()))
		},
		BaoDelete: func(ctx context.Context, n *v1alpha1.OpenBaoNamespace) error {
			return bao.DeleteNamespace(ctx, n.BaoName(), baoclient.WithNamespace(n.OpenBaoNamespace()))
		},
		BaoDeleteIdentity: func(ctx context.Context, _ *v1alpha1.OpenBaoNamespace, name, namespace string) error {
			return bao.DeleteNamespace(ctx, name, baoclient.WithNamespace(namespace))
		},
		CheckCollision: func(ctx context.Context, n *v1alpha1.OpenBaoNamespace) error {
			return checkNamespaceCollision(ctx, cl, n)
		},
	}
}

// checkNamespaceCollision returns ErrNameCollision when another
// OpenBaoNamespace CR (different UID) targets the same bao-side
// namespace. The collision tuple is (parent-OpenBaoNamespace,
// BaoName) — same name in different parent contexts is not a
// collision (e.g. acme/sub and globex/sub are distinct bao
// namespaces).
//
// Tie-break: older CreationTimestamp wins; on tie, lex order of
// <namespace>/<name> wins. Mirrors the Policy / KAER / Mount
// collision logic.
func checkNamespaceCollision(ctx context.Context, cl client.Client, n *v1alpha1.OpenBaoNamespace) error {
	var all v1alpha1.OpenBaoNamespaceList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoNamespaces for collision check: %v",
			resource.ErrInternal, err)
	}
	targetName := n.BaoName()
	targetParent := n.OpenBaoNamespace()
	mineKey := n.Namespace + "/" + n.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == n.UID {
			continue
		}
		if other.BaoName() != targetName {
			continue
		}
		if other.OpenBaoNamespace() != targetParent {
			continue
		}
		var otherWins bool
		switch {
		case other.CreationTimestamp.Before(&n.CreationTimestamp):
			otherWins = true
		case n.CreationTimestamp.Before(&other.CreationTimestamp):
			otherWins = false
		default:
			otherKey := other.Namespace + "/" + other.Name
			otherWins = otherKey < mineKey
		}
		if otherWins {
			return fmt.Errorf("%w: bao namespace %q (parent %q) already owned by OpenBaoNamespace %s/%s",
				resource.ErrNameCollision, targetName, targetParent, other.Namespace, other.Name)
		}
	}
	return nil
}

// SetupWithManager registers the controller with a
// GenerationChangedPredicate so status writes do not trigger
// re-reconciles. The base reconciler's success path returns
// RequeueAfter: PeriodicInterval (5m), so this controller self-heals
// against out-of-band bao-namespace deletion without per-controller
// wiring.
func (r *OpenBaoNamespaceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoNamespace{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
