package openbaoidentitytokenrole

import (
	"context"
	"errors"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1alpha1 "github.com/stakater-ab/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater-ab/openbao-config-operator/internal/client"
	"github.com/stakater-ab/openbao-config-operator/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoidentitytokenroles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoidentitytokenroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoidentitytokenroles/finalizers,verbs=update

const OpenBaoIdentityTokenRoleFinalizer = "openbaoidentitytokenrole.security.mto.stakater.com/finalizer"

type OpenBaoIdentityTokenRoleReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoIdentityTokenRole]
}

func NewOpenBaoIdentityTokenRoleReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoIdentityTokenRoleReconciler {
	return &OpenBaoIdentityTokenRoleReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoIdentityTokenRole](mgr, OpenBaoIdentityTokenRoleFinalizer,
			OpenBaoIdentityTokenRoleHandlers(mgr.GetClient(), bao)),
	}
}

func OpenBaoIdentityTokenRoleHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoIdentityTokenRole] {
	return resource.Handlers[*v1alpha1.OpenBaoIdentityTokenRole]{
		NewInstance: func() *v1alpha1.OpenBaoIdentityTokenRole {
			return &v1alpha1.OpenBaoIdentityTokenRole{}
		},

		BaoGet: func(ctx context.Context, r *v1alpha1.OpenBaoIdentityTokenRole) (map[string]any, error) {
			ns := baoclient.WithNamespace(r.OpenBaoNamespace())
			cur, err := bao.ReadIdentityTokenRole(ctx, r.BaoName(), ns)
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{"role": cur}, nil
		},

		BaoWrite: func(ctx context.Context, r *v1alpha1.OpenBaoIdentityTokenRole) (resource.StatusMutator[*v1alpha1.OpenBaoIdentityTokenRole], error) {
			if err := checkITRCollision(ctx, cl, r); err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(r.OpenBaoNamespace())
			return nil, bao.WriteIdentityTokenRole(ctx, r.BaoName(), r.ToBaoSpec(), ns)
		},

		BaoDelete: func(ctx context.Context, r *v1alpha1.OpenBaoIdentityTokenRole) error {
			return bao.DeleteIdentityTokenRole(ctx, r.BaoName(),
				baoclient.WithNamespace(r.OpenBaoNamespace()))
		},

		BaoDeleteIdentity: func(ctx context.Context, _ *v1alpha1.OpenBaoIdentityTokenRole, name, namespace string) error {
			return bao.DeleteIdentityTokenRole(ctx, name, baoclient.WithNamespace(namespace))
		},

		CheckCollision: func(ctx context.Context, r *v1alpha1.OpenBaoIdentityTokenRole) error {
			return checkITRCollision(ctx, cl, r)
		},
	}
}

// checkITRCollision returns ErrNameCollision when another
// OpenBaoIdentityTokenRole CR (different UID) targets the same
// (BaoName, openbaoNamespace) tuple.
func checkITRCollision(ctx context.Context, cl client.Client, r *v1alpha1.OpenBaoIdentityTokenRole) error {
	var all v1alpha1.OpenBaoIdentityTokenRoleList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoIdentityTokenRoles for collision check: %v",
			resource.ErrInternal, err)
	}
	targetName := r.BaoName()
	targetNS := r.OpenBaoNamespace()
	mineKey := r.Namespace + "/" + r.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == r.UID {
			continue
		}
		if other.BaoName() != targetName {
			continue
		}
		if other.OpenBaoNamespace() != targetNS {
			continue
		}
		var otherWins bool
		switch {
		case other.CreationTimestamp.Before(&r.CreationTimestamp):
			otherWins = true
		case r.CreationTimestamp.Before(&other.CreationTimestamp):
			otherWins = false
		default:
			otherKey := other.Namespace + "/" + other.Name
			otherWins = otherKey < mineKey
		}
		if otherWins {
			return fmt.Errorf("%w: bao identity-token role %q (ns=%q) already owned by OpenBaoIdentityTokenRole %s/%s",
				resource.ErrNameCollision, targetName, targetNS, other.Namespace, other.Name)
		}
	}
	return nil
}

func (r *OpenBaoIdentityTokenRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoIdentityTokenRole{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
