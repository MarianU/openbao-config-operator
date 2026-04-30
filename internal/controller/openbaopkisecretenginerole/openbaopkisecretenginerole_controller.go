package openbaopkisecretenginerole

import (
	"context"
	"errors"
	"fmt"
	"os"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaopkisecretengineroles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaopkisecretengineroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaopkisecretengineroles/finalizers,verbs=update

const OpenBaoPKISecretEngineRoleFinalizer = "openbaopkisecretenginerole.security.mto.stakater.com/finalizer"

type OpenBaoPKISecretEngineRoleReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoPKISecretEngineRole]
}

func NewOpenBaoPKISecretEngineRoleReconciler(mgr ctrl.Manager) (*OpenBaoPKISecretEngineRoleReconciler, error) {
	bao, err := newBaoFromEnv()
	if err != nil {
		return nil, err
	}
	return NewOpenBaoPKISecretEngineRoleReconcilerWithClient(mgr, bao), nil
}

func NewOpenBaoPKISecretEngineRoleReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoPKISecretEngineRoleReconciler {
	return &OpenBaoPKISecretEngineRoleReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoPKISecretEngineRole](
			mgr, OpenBaoPKISecretEngineRoleFinalizer,
			OpenBaoPKISecretEngineRoleHandlers(mgr.GetClient(), bao)),
	}
}

func OpenBaoPKISecretEngineRoleHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoPKISecretEngineRole] {
	return resource.Handlers[*v1alpha1.OpenBaoPKISecretEngineRole]{
		NewInstance: func() *v1alpha1.OpenBaoPKISecretEngineRole {
			return &v1alpha1.OpenBaoPKISecretEngineRole{}
		},

		BaoGet: func(ctx context.Context, p *v1alpha1.OpenBaoPKISecretEngineRole) (map[string]any, error) {
			ns := baoclient.WithNamespace(p.OpenBaoNamespace())
			role, err := bao.ReadPKIRole(ctx, p.Spec.Path, p.BaoName(), ns)
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{"role": role}, nil
		},

		BaoWrite: func(ctx context.Context, p *v1alpha1.OpenBaoPKISecretEngineRole) (resource.StatusMutator[*v1alpha1.OpenBaoPKISecretEngineRole], error) {
			if err := checkPKIRoleCollision(ctx, cl, p); err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(p.OpenBaoNamespace())
			if err := bao.WritePKIRole(ctx, p.Spec.Path, p.BaoName(), p.ToBaoSpec(), ns); err != nil {
				return nil, err
			}
			// Stamp the bao mount path on status so a subsequent
			// rename that also moves the role to a new mount can
			// clean up the previous (path, name) tuple — the base's
			// rename tracker only carries name+namespace.
			pathSnapshot := p.Spec.Path
			return func(cur *v1alpha1.OpenBaoPKISecretEngineRole) {
				cur.Status.LastWrittenPath = pathSnapshot
			}, nil
		},

		BaoDelete: func(ctx context.Context, p *v1alpha1.OpenBaoPKISecretEngineRole) error {
			ns := baoclient.WithNamespace(p.OpenBaoNamespace())
			return bao.DeletePKIRole(ctx, p.Spec.Path, p.BaoName(), ns)
		},

		BaoDeleteIdentity: func(ctx context.Context, p *v1alpha1.OpenBaoPKISecretEngineRole, name, namespace string) error {
			// Use the bao mount path that was active when (name,
			// namespace) was last written, NOT the current spec.Path.
			// A spec edit that changes both name AND path in one go
			// would otherwise target the new mount and silently 404,
			// orphaning the role at the old (path, name).
			//
			// Fall back to the current spec.Path when status hasn't
			// captured the path yet (first-write scenarios where the
			// rename happened before any successful BaoGet+patch
			// stamped LastWrittenPath).
			path := p.Status.LastWrittenPath
			if path == "" {
				path = p.Spec.Path
			}
			return bao.DeletePKIRole(ctx, path, name, baoclient.WithNamespace(namespace))
		},

		CheckCollision: func(ctx context.Context, p *v1alpha1.OpenBaoPKISecretEngineRole) error {
			return checkPKIRoleCollision(ctx, cl, p)
		},
	}
}

// checkPKIRoleCollision returns ErrNameCollision when another
// OpenBaoPKISecretEngineRole CR (different UID) targets the same
// (openbaoNamespace, mount path, role name) tuple. Two CRs at the
// same role name on different mounts don't collide because the bao
// path differs.
func checkPKIRoleCollision(ctx context.Context, cl client.Client, p *v1alpha1.OpenBaoPKISecretEngineRole) error {
	var all v1alpha1.OpenBaoPKISecretEngineRoleList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoPKISecretEngineRoles for collision check: %v",
			resource.ErrInternal, err)
	}
	targetMount := p.Spec.Path
	targetName := p.BaoName()
	targetNS := p.OpenBaoNamespace()
	mineKey := p.Namespace + "/" + p.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == p.UID {
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
		case other.CreationTimestamp.Before(&p.CreationTimestamp):
			otherWins = true
		case p.CreationTimestamp.Before(&other.CreationTimestamp):
			otherWins = false
		default:
			otherKey := other.Namespace + "/" + other.Name
			otherWins = otherKey < mineKey
		}
		if otherWins {
			return fmt.Errorf("%w: PKI role %q (mount=%q, ns=%q) already owned by OpenBaoPKISecretEngineRole %s/%s",
				resource.ErrNameCollision, targetName, targetMount, targetNS, other.Namespace, other.Name)
		}
	}
	return nil
}

func (r *OpenBaoPKISecretEngineRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoPKISecretEngineRole{}).
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
		return nil, fmt.Errorf("set VAULT_ADDR/VAULT_TOKEN (or BAO_ADDR/BAO_TOKEN) for OpenBaoPKISecretEngineRoleReconciler")
	}
	return baoclient.NewHTTPClient(addr, token)
}
