package openbaogroup

import (
	"context"
	"errors"
	"fmt"
	"strings"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1alpha1 "github.com/stakater-ab/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater-ab/openbao-config-operator/internal/client"
	"github.com/stakater-ab/openbao-config-operator/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaogroups,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaogroups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaogroups/finalizers,verbs=update

const OpenBaoGroupFinalizer = "openbaogroup.security.mto.stakater.com/finalizer"

type OpenBaoGroupReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoGroup]
}

func NewOpenBaoGroupReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoGroupReconciler {
	return &OpenBaoGroupReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoGroup](mgr, OpenBaoGroupFinalizer,
			OpenBaoGroupHandlers(mgr.GetClient(), bao)),
	}
}

func OpenBaoGroupHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoGroup] {
	return resource.Handlers[*v1alpha1.OpenBaoGroup]{
		NewInstance: func() *v1alpha1.OpenBaoGroup { return &v1alpha1.OpenBaoGroup{} },

		BaoGet: func(ctx context.Context, g *v1alpha1.OpenBaoGroup) (map[string]any, error) {
			ns := baoclient.WithNamespace(g.OpenBaoNamespace())
			cur, err := bao.ReadIdentityGroup(ctx, g.BaoName(), ns)
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{"group": cur}, nil
		},

		BaoWrite: func(ctx context.Context, g *v1alpha1.OpenBaoGroup) (resource.StatusMutator[*v1alpha1.OpenBaoGroup], error) {
			if err := checkGroupNameCollision(ctx, cl, g); err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(g.OpenBaoNamespace())
			// Probe bao before write. Three things hang on this read:
			//
			// 1. Type immutability — bao does not allow group type to
			//    change in place; surface a clear error rather than
			//    flap the drift loop forever.
			// 2. ID staleness — `status.GroupID` may point at a group
			//    that was deleted out of band. Sending the stale id on
			//    write makes bao reject with 400 "invalid group ID".
			//    On a clean miss we drop the id; on a hit we use bao's
			//    actual id, which may differ if the group was recreated
			//    OOB with a fresh id.
			existing, err := bao.ReadIdentityGroup(ctx, g.BaoName(), ns)
			spec := g.ToBaoSpec()
			switch {
			case err == nil && !strings.EqualFold(existing.Type, g.EffectiveType()):
				return nil, fmt.Errorf("%w: bao group %q has type %q, spec selects %q — "+
					"group type is immutable; delete the CR (and bao group) to switch",
					resource.ErrInternal, g.BaoName(), existing.Type, g.EffectiveType())
			case err == nil:
				spec.ID = existing.ID
			case errors.Is(err, baoclient.ErrNotFound):
				spec.ID = ""
			default:
				return nil, err
			}
			out, werr := bao.WriteIdentityGroup(ctx, spec, ns)
			if werr != nil {
				return nil, werr
			}
			groupID := out.ID
			return func(cur *v1alpha1.OpenBaoGroup) {
				if groupID != "" {
					cur.Status.GroupID = groupID
				}
			}, nil
		},

		BaoDelete: func(ctx context.Context, g *v1alpha1.OpenBaoGroup) error {
			ns := baoclient.WithNamespace(g.OpenBaoNamespace())
			return bao.DeleteIdentityGroup(ctx, g.BaoName(), ns)
		},

		BaoDeleteIdentity: func(ctx context.Context, _ *v1alpha1.OpenBaoGroup, name, namespace string) error {
			return bao.DeleteIdentityGroup(ctx, name, baoclient.WithNamespace(namespace))
		},

		CheckCollision: func(ctx context.Context, g *v1alpha1.OpenBaoGroup) error {
			return checkGroupNameCollision(ctx, cl, g)
		},

		// Backfill: if a previous BaoWrite stamped the group id but
		// status.GroupID was lost (CR re-created from manifest, etc.),
		// the read-only path would never re-populate it. Recover the
		// id from the live bao read.
		Backfill: func(g *v1alpha1.OpenBaoGroup, current map[string]any) resource.StatusMutator[*v1alpha1.OpenBaoGroup] {
			cur, ok := current["group"].(*baoclient.IdentityGroup)
			if !ok || cur == nil || cur.ID == "" || cur.ID == g.Status.GroupID {
				return nil
			}
			id := cur.ID
			return func(c *v1alpha1.OpenBaoGroup) { c.Status.GroupID = id }
		},
	}
}

// checkGroupNameCollision returns ErrNameCollision when another
// OpenBaoGroup CR (different UID) targets the same (OpenBaoNamespace,
// BaoName) tuple. Bao groups are namespaced via X-Vault-Namespace, so
// same-name in different bao namespaces is not a collision.
func checkGroupNameCollision(ctx context.Context, cl client.Client, g *v1alpha1.OpenBaoGroup) error {
	var all v1alpha1.OpenBaoGroupList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoGroups for collision check: %v",
			resource.ErrInternal, err)
	}
	targetName := g.BaoName()
	targetNS := g.OpenBaoNamespace()
	mineKey := g.Namespace + "/" + g.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == g.UID {
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
		case other.CreationTimestamp.Before(&g.CreationTimestamp):
			otherWins = true
		case g.CreationTimestamp.Before(&other.CreationTimestamp):
			otherWins = false
		default:
			otherKey := other.Namespace + "/" + other.Name
			otherWins = otherKey < mineKey
		}
		if otherWins {
			return fmt.Errorf("%w: bao group %q (ns=%q) already owned by OpenBaoGroup %s/%s",
				resource.ErrNameCollision, targetName, targetNS, other.Namespace, other.Name)
		}
	}
	return nil
}

func (r *OpenBaoGroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoGroup{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
