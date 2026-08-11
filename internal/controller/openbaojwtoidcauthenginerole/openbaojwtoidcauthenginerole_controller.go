package openbaojwtoidcauthenginerole

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

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaojwtoidcauthengineroles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaojwtoidcauthengineroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaojwtoidcauthengineroles/finalizers,verbs=update

const OpenBaoJWTOIDCAuthEngineRoleFinalizer = "openbaojwtoidcauthenginerole.security.mto.stakater.com/finalizer"

type OpenBaoJWTOIDCAuthEngineRoleReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoJWTOIDCAuthEngineRole]
}

func NewOpenBaoJWTOIDCAuthEngineRoleReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoJWTOIDCAuthEngineRoleReconciler {
	return &OpenBaoJWTOIDCAuthEngineRoleReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoJWTOIDCAuthEngineRole](mgr, OpenBaoJWTOIDCAuthEngineRoleFinalizer,
			OpenBaoJWTOIDCAuthEngineRoleHandlers(mgr.GetClient(), bao)),
	}
}

func OpenBaoJWTOIDCAuthEngineRoleHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoJWTOIDCAuthEngineRole] {
	return resource.Handlers[*v1alpha1.OpenBaoJWTOIDCAuthEngineRole]{
		NewInstance: func() *v1alpha1.OpenBaoJWTOIDCAuthEngineRole {
			return &v1alpha1.OpenBaoJWTOIDCAuthEngineRole{}
		},

		BaoGet: func(ctx context.Context, r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) (map[string]any, error) {
			ns := baoclient.WithNamespace(r.OpenBaoNamespace())
			cur, err := bao.ReadJWTOIDCRole(ctx, r.Spec.Path, r.BaoName(), ns)
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{"role": cur}, nil
		},

		BaoWrite: func(ctx context.Context, r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) (resource.StatusMutator[*v1alpha1.OpenBaoJWTOIDCAuthEngineRole], error) {
			if err := checkRoleCollision(ctx, cl, r); err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(r.OpenBaoNamespace())
			if err := bao.WriteJWTOIDCRole(ctx, r.Spec.Path, r.BaoName(), r.ToBaoSpec(), ns); err != nil {
				return nil, err
			}
			pathSnapshot := r.Spec.Path
			return func(cur *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) {
				cur.Status.LastWrittenPath = pathSnapshot
			}, nil
		},

		BaoDelete: func(ctx context.Context, r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) error {
			return bao.DeleteJWTOIDCRole(ctx, r.Spec.Path, r.BaoName(),
				baoclient.WithNamespace(r.OpenBaoNamespace()))
		},

		BaoDeleteIdentity: func(ctx context.Context, r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole, name, namespace string) error {
			path := r.Status.LastWrittenPath
			if path == "" {
				path = r.Spec.Path
			}
			return bao.DeleteJWTOIDCRole(ctx, path, name,
				baoclient.WithNamespace(namespace))
		},

		CheckCollision: func(ctx context.Context, r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) error {
			return checkRoleCollision(ctx, cl, r)
		},
	}
}

func checkRoleCollision(ctx context.Context, cl client.Client, r *v1alpha1.OpenBaoJWTOIDCAuthEngineRole) error {
	var all v1alpha1.OpenBaoJWTOIDCAuthEngineRoleList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoJWTOIDCAuthEngineRoles for collision check: %v",
			resource.ErrInternal, err)
	}
	targetMount := r.Spec.Path
	targetName := r.BaoName()
	targetNS := r.OpenBaoNamespace()
	mineKey := r.Namespace + "/" + r.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == r.UID {
			continue
		}
		if other.Spec.Path != targetMount {
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
			return fmt.Errorf("%w: bao jwt/oidc role %q (mount=%q, ns=%q) already owned by OpenBaoJWTOIDCAuthEngineRole %s/%s",
				resource.ErrNameCollision, targetName, targetMount, targetNS,
				other.Namespace, other.Name)
		}
	}
	return nil
}

func (r *OpenBaoJWTOIDCAuthEngineRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoJWTOIDCAuthEngineRole{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
