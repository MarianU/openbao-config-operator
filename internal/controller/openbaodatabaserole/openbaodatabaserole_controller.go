package openbaodatabaserole

import (
	"context"
	"errors"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaodatabaseroles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaodatabaseroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaodatabaseroles/finalizers,verbs=update

const OpenBaoDatabaseRoleFinalizer = "openbaodatabaserole.security.mto.stakater.com/finalizer"

type OpenBaoDatabaseRoleReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoDatabaseRole]
	cl client.Client
}

func NewOpenBaoDatabaseRoleReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoDatabaseRoleReconciler {
	return &OpenBaoDatabaseRoleReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoDatabaseRole](mgr, OpenBaoDatabaseRoleFinalizer,
			OpenBaoDatabaseRoleHandlers(mgr.GetClient(), bao)),
		cl: mgr.GetClient(),
	}
}

func OpenBaoDatabaseRoleHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoDatabaseRole] {
	return resource.Handlers[*v1alpha1.OpenBaoDatabaseRole]{
		NewInstance: func() *v1alpha1.OpenBaoDatabaseRole {
			return &v1alpha1.OpenBaoDatabaseRole{}
		},

		BaoGet: func(ctx context.Context, r *v1alpha1.OpenBaoDatabaseRole) (map[string]any, error) {
			cur, err := bao.ReadDatabaseRole(ctx, r.Mount(), r.BaoName(),
				baoclient.WithNamespace(r.OpenBaoNamespace()))
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{"role": cur}, nil
		},

		BaoWrite: func(ctx context.Context, r *v1alpha1.OpenBaoDatabaseRole) (resource.StatusMutator[*v1alpha1.OpenBaoDatabaseRole], error) {
			if err := checkCollision(ctx, cl, r); err != nil {
				return nil, err
			}
			if err := bao.WriteDatabaseRole(ctx, r.Mount(), r.BaoName(), r.ToBaoSpec(),
				baoclient.WithNamespace(r.OpenBaoNamespace())); err != nil {
				return nil, err
			}
			// Stamp the bao mount so a simultaneous spec.mount + spec.name
			// edit cleans up the previous role at its real location.
			mountSnapshot := r.Mount()
			return func(cur *v1alpha1.OpenBaoDatabaseRole) {
				cur.Status.LastWrittenMount = mountSnapshot
			}, nil
		},

		BaoDelete: func(ctx context.Context, r *v1alpha1.OpenBaoDatabaseRole) error {
			return bao.DeleteDatabaseRole(ctx, r.Mount(), r.BaoName(),
				baoclient.WithNamespace(r.OpenBaoNamespace()))
		},

		BaoDeleteIdentity: func(ctx context.Context, r *v1alpha1.OpenBaoDatabaseRole, name, namespace string) error {
			mount := r.Status.LastWrittenMount
			if mount == "" {
				mount = r.Mount()
			}
			return bao.DeleteDatabaseRole(ctx, mount, name,
				baoclient.WithNamespace(namespace))
		},

		CheckCollision: func(ctx context.Context, r *v1alpha1.OpenBaoDatabaseRole) error {
			return checkCollision(ctx, cl, r)
		},
	}
}

// checkCollision returns ErrNameCollision when another CR (different UID)
// targets the same (openbaoNamespace, mount, role name) tuple.
func checkCollision(ctx context.Context, cl client.Client, r *v1alpha1.OpenBaoDatabaseRole) error {
	var all v1alpha1.OpenBaoDatabaseRoleList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoDatabaseRoles for collision check: %v",
			resource.ErrInternal, err)
	}
	targetMount := r.Mount()
	targetName := r.BaoName()
	targetNS := r.OpenBaoNamespace()
	mineKey := r.Namespace + "/" + r.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == r.UID {
			continue
		}
		if other.Mount() != targetMount {
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
			return fmt.Errorf("%w: database role %q (mount=%q, ns=%q) already owned by OpenBaoDatabaseRole %s/%s",
				resource.ErrNameCollision, targetName, targetMount, targetNS,
				other.Namespace, other.Name)
		}
	}
	return nil
}

func (r *OpenBaoDatabaseRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoDatabaseRole{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
