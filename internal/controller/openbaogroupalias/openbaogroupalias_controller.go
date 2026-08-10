package openbaogroupalias

import (
	"context"
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/stakater-ab/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater-ab/openbao-config-operator/internal/client"
	"github.com/stakater-ab/openbao-config-operator/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaogroupaliases,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaogroupaliases/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaogroupaliases/finalizers,verbs=update
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaogroups,verbs=get;list;watch

const OpenBaoGroupAliasFinalizer = "openbaogroupalias.security.mto.stakater.com/finalizer"

type OpenBaoGroupAliasReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoGroupAlias]
	cl client.Client
}

func NewOpenBaoGroupAliasReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoGroupAliasReconciler {
	return &OpenBaoGroupAliasReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoGroupAlias](mgr, OpenBaoGroupAliasFinalizer,
			OpenBaoGroupAliasHandlers(mgr.GetClient(), bao)),
		cl: mgr.GetClient(),
	}
}

func OpenBaoGroupAliasHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoGroupAlias] {
	return resource.Handlers[*v1alpha1.OpenBaoGroupAlias]{
		NewInstance: func() *v1alpha1.OpenBaoGroupAlias { return &v1alpha1.OpenBaoGroupAlias{} },

		BaoGet: func(ctx context.Context, a *v1alpha1.OpenBaoGroupAlias) (map[string]any, error) {
			ns := baoclient.WithNamespace(a.OpenBaoNamespace())

			// Bao keys aliases by id. When status.AliasID is set
			// (post-first-write or post-Backfill), read by id —
			// fastest, exact. When it's empty, scan by
			// (name, mount_accessor) so a CR re-applied from manifest
			// (status lost) recovers cleanly.
			if a.Status.AliasID != "" {
				cur, err := bao.ReadIdentityGroupAliasByID(ctx, a.Status.AliasID, ns)
				if errors.Is(err, baoclient.ErrNotFound) {
					return nil, resource.ErrBaoNotFound
				}
				if err != nil {
					return nil, err
				}
				return map[string]any{"alias": cur}, nil
			}
			cur, err := bao.FindIdentityGroupAlias(ctx, a.BaoName(), a.MountAccessor(), ns)
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{"alias": cur}, nil
		},

		BaoWrite: func(ctx context.Context, a *v1alpha1.OpenBaoGroupAlias) (resource.StatusMutator[*v1alpha1.OpenBaoGroupAlias], error) {
			if err := checkAliasCollision(ctx, cl, a); err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(a.OpenBaoNamespace())
			// Probe before write. status.AliasID may point at an alias
			// that was deleted out of band; sending the stale id makes
			// bao reject with 400 "invalid alias ID". On a hit, use
			// bao's actual id (may differ if the alias was recreated
			// OOB with a fresh id). On a clean miss, drop the id so
			// bao mints a new one.
			spec := a.ToBaoSpec()
			if spec.ID != "" {
				existing, rerr := bao.ReadIdentityGroupAliasByID(ctx, spec.ID, ns)
				switch {
				case rerr == nil:
					spec.ID = existing.ID
				case errors.Is(rerr, baoclient.ErrNotFound):
					spec.ID = ""
				default:
					return nil, rerr
				}
			}
			// If we still don't have an id, try locating an existing
			// alias by (name, mount_accessor) — covers the case where
			// status was lost but the alias is already in bao.
			if spec.ID == "" {
				if found, ferr := bao.FindIdentityGroupAlias(ctx, a.BaoName(), a.MountAccessor(), ns); ferr == nil && found != nil {
					spec.ID = found.ID
				}
			}
			out, err := bao.WriteIdentityGroupAlias(ctx, spec, ns)
			if err != nil {
				return nil, err
			}
			id := out.ID
			mountSnapshot := a.MountAccessor()
			canonicalSnapshot := a.Status.ResolvedCanonicalID
			return func(cur *v1alpha1.OpenBaoGroupAlias) {
				if id != "" {
					cur.Status.AliasID = id
				}
				cur.Status.LastWrittenMountAccessor = mountSnapshot
				cur.Status.ResolvedCanonicalID = canonicalSnapshot
			}, nil
		},

		BaoDelete: func(ctx context.Context, a *v1alpha1.OpenBaoGroupAlias) error {
			if a.Status.AliasID == "" {
				// Defense in depth: status.baoWritten gates this
				// path at the base level. Reaching here without an
				// id means the CR never wrote.
				return nil
			}
			return bao.DeleteIdentityGroupAliasByID(ctx, a.Status.AliasID,
				baoclient.WithNamespace(a.OpenBaoNamespace()))
		},

		BaoDeleteIdentity: func(ctx context.Context, a *v1alpha1.OpenBaoGroupAlias, _, _ string) error {
			// Aliases are keyed by bao-side id, not by (name, mount,
			// namespace). A spec.name rename is therefore an
			// in-place update on the SAME bao record — the rename
			// detector in the base fires (because LastWrittenBaoName
			// changed), but there is no previous bao object to clean
			// up. Acting on the rename signal here would delete the
			// alias we just renamed, since BaoWrite already mutated
			// the record at status.AliasID.
			//
			// spec.openbaoNamespace or spec.mountAccessor edits would
			// strand an orphan in the old namespace/mount; users
			// hitting that edge case should delete + re-create the
			// CR. The shared base's BaoDelete (called on CR delete)
			// cleans up the alias at status.AliasID.
			return nil
		},

		CheckCollision: func(ctx context.Context, a *v1alpha1.OpenBaoGroupAlias) error {
			return checkAliasCollision(ctx, cl, a)
		},

		// Backfill: a CR re-applied from manifest loses status.AliasID;
		// recover it from the matching bao read.
		Backfill: func(a *v1alpha1.OpenBaoGroupAlias, current map[string]any) resource.StatusMutator[*v1alpha1.OpenBaoGroupAlias] {
			cur, ok := current["alias"].(*baoclient.IdentityGroupAlias)
			if !ok || cur == nil {
				return nil
			}
			needsAliasID := cur.ID != "" && cur.ID != a.Status.AliasID
			needsMount := cur.MountAccessor != "" && cur.MountAccessor != a.Status.LastWrittenMountAccessor
			needsCanonical := cur.CanonicalID != "" && cur.CanonicalID != a.Status.ResolvedCanonicalID
			if !needsAliasID && !needsMount && !needsCanonical {
				return nil
			}
			id := cur.ID
			mount := cur.MountAccessor
			canonical := cur.CanonicalID
			return func(c *v1alpha1.OpenBaoGroupAlias) {
				if id != "" {
					c.Status.AliasID = id
				}
				if mount != "" {
					c.Status.LastWrittenMountAccessor = mount
				}
				if canonical != "" {
					c.Status.ResolvedCanonicalID = canonical
				}
			}
		},
	}
}

// checkAliasCollision returns ErrNameCollision when another
// OpenBaoGroupAlias CR (different UID) targets the same
// (OpenBaoNamespace, MountAccessor, BaoName) tuple. Bao stores aliases
// keyed by (name, mount_accessor); same name on a different mount is
// not a collision.
func checkAliasCollision(ctx context.Context, cl client.Client, a *v1alpha1.OpenBaoGroupAlias) error {
	var all v1alpha1.OpenBaoGroupAliasList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoGroupAliases for collision check: %v",
			resource.ErrInternal, err)
	}
	targetName := a.BaoName()
	targetMount := a.MountAccessor()
	targetNS := a.OpenBaoNamespace()
	mineKey := a.Namespace + "/" + a.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == a.UID {
			continue
		}
		if other.BaoName() != targetName {
			continue
		}
		if other.MountAccessor() != targetMount {
			continue
		}
		if other.OpenBaoNamespace() != targetNS {
			continue
		}
		var otherWins bool
		switch {
		case other.CreationTimestamp.Before(&a.CreationTimestamp):
			otherWins = true
		case a.CreationTimestamp.Before(&other.CreationTimestamp):
			otherWins = false
		default:
			otherKey := other.Namespace + "/" + other.Name
			otherWins = otherKey < mineKey
		}
		if otherWins {
			return fmt.Errorf("%w: bao group-alias (mount=%q, name=%q, ns=%q) already owned by OpenBaoGroupAlias %s/%s",
				resource.ErrNameCollision, targetMount, targetName, targetNS,
				other.Namespace, other.Name)
		}
	}
	return nil
}

// SetupWithManager wires this controller and watches for parent
// OpenBaoGroup status changes. When an OpenBaoGroup's status.GroupID
// stamps for the first time (or changes), aliases referring to it
// must re-resolve their canonicalId.
func (r *OpenBaoGroupAliasReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoGroupAlias{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(
			&v1alpha1.OpenBaoGroup{},
			handler.EnqueueRequestsFromMapFunc(r.aliasesReferencingGroup),
		).
		Complete(r)
}

// aliasesReferencingGroup returns reconcile requests for every alias
// CR whose canonicalGroupRef points at the given OpenBaoGroup. Used
// to wake aliases when the parent group's status.GroupID is stamped
// or rotated.
func (r *OpenBaoGroupAliasReconciler) aliasesReferencingGroup(ctx context.Context, obj client.Object) []reconcile.Request {
	g, ok := obj.(*v1alpha1.OpenBaoGroup)
	if !ok {
		return nil
	}
	var aliases v1alpha1.OpenBaoGroupAliasList
	if err := r.cl.List(ctx, &aliases); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range aliases.Items {
		a := &aliases.Items[i]
		if a.Spec.CanonicalGroupRef == nil {
			continue
		}
		refNS := a.Spec.CanonicalGroupRef.Namespace
		if refNS == "" {
			refNS = a.Namespace
		}
		if refNS == g.Namespace && a.Spec.CanonicalGroupRef.Name == g.Name {
			out = append(out, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: a.Namespace, Name: a.Name},
			})
		}
	}
	return out
}
