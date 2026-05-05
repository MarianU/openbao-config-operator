package openbaoauthmethod

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

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoauthmethods,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoauthmethods/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoauthmethods/finalizers,verbs=update

const OpenBaoAuthMethodFinalizer = "openbaoauthmethod.security.mto.stakater.com/finalizer"

type OpenBaoAuthMethodReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoAuthMethod]
}

func NewOpenBaoAuthMethodReconciler(mgr ctrl.Manager) (*OpenBaoAuthMethodReconciler, error) {
	bao, err := newBaoFromEnv()
	if err != nil {
		return nil, err
	}
	return NewOpenBaoAuthMethodReconcilerWithClient(mgr, bao), nil
}

func NewOpenBaoAuthMethodReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoAuthMethodReconciler {
	return &OpenBaoAuthMethodReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoAuthMethod](mgr, OpenBaoAuthMethodFinalizer,
			OpenBaoAuthMethodHandlers(mgr.GetClient(), bao)),
	}
}

func OpenBaoAuthMethodHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoAuthMethod] {
	return resource.Handlers[*v1alpha1.OpenBaoAuthMethod]{
		NewInstance: func() *v1alpha1.OpenBaoAuthMethod { return &v1alpha1.OpenBaoAuthMethod{} },

		BaoGet: func(ctx context.Context, m *v1alpha1.OpenBaoAuthMethod) (map[string]any, error) {
			ns := baoclient.WithNamespace(m.OpenBaoNamespace())
			cur, err := bao.GetAuthMethod(ctx, m.Spec.Path, ns)
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{"mount": cur}, nil
		},

		BaoWrite: func(ctx context.Context, m *v1alpha1.OpenBaoAuthMethod) (resource.StatusMutator[*v1alpha1.OpenBaoAuthMethod], error) {
			if err := checkAuthMethodCollision(ctx, cl, m); err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(m.OpenBaoNamespace())

			// Bao's POST sys/auth creates only — re-POST returns
			// 400 "already in use" which the wrapper swallows as
			// idempotent success. Probe with GetAuthMethod first;
			// route to enable on missing, tune on present.
			//
			// Type immutability: bao does not allow auth-method
			// type to change in place. Detect a type mismatch and
			// surface a clear error rather than letting drift
			// loop forever.
			existing, err := bao.GetAuthMethod(ctx, m.Spec.Path, ns)
			switch {
			case err == nil && existing.Type != m.Spec.Type:
				return nil, fmt.Errorf("%w: bao auth mount %q has type %q, spec selects %q — "+
					"auth-method type is immutable; delete the CR (and the bao mount) and recreate",
					resource.ErrInternal, m.Spec.Path, existing.Type, m.Spec.Type)
			case err == nil:
				if werr := bao.TuneAuthMethod(ctx, m.Spec.Path, m.ToBaoSpec(), ns); werr != nil {
					return nil, werr
				}
			case errors.Is(err, baoclient.ErrNotFound):
				if werr := bao.EnableAuthMethod(ctx, m.Spec.Path, m.ToBaoSpec(), ns); werr != nil {
					return nil, werr
				}
			default:
				return nil, err
			}

			// Re-read after the write to pick up the bao-stamped
			// accessor. Best-effort — a transient read failure
			// leaves status as-is and the next reconcile's
			// Backfill picks the accessor up.
			return accessorMutator(ctx, bao, m.Spec.Path, ns), nil
		},

		BaoDelete: func(ctx context.Context, m *v1alpha1.OpenBaoAuthMethod) error {
			return bao.DisableAuthMount(ctx, m.Spec.Path,
				baoclient.WithNamespace(m.OpenBaoNamespace()))
		},

		BaoDeleteIdentity: func(ctx context.Context, _ *v1alpha1.OpenBaoAuthMethod, name, namespace string) error {
			return bao.DisableAuthMount(ctx, name, baoclient.WithNamespace(namespace))
		},

		CheckCollision: func(ctx context.Context, m *v1alpha1.OpenBaoAuthMethod) error {
			return checkAuthMethodCollision(ctx, cl, m)
		},

		// Backfill stamps the accessor when state matches and the
		// CR's status is missing or stale. status.MountAccessor is
		// load-bearing for downstream CRs (OpenBaoGroupAlias binds
		// by mount accessor).
		Backfill: func(m *v1alpha1.OpenBaoAuthMethod, current map[string]any) resource.StatusMutator[*v1alpha1.OpenBaoAuthMethod] {
			cur, ok := current["mount"].(*baoclient.AuthMethodMount)
			if !ok || cur == nil || cur.Accessor == "" || cur.Accessor == m.Status.MountAccessor {
				return nil
			}
			accessor := cur.Accessor
			return func(c *v1alpha1.OpenBaoAuthMethod) {
				c.Status.MountAccessor = accessor
			}
		},
	}
}

// accessorMutator returns a StatusMutator that stamps the
// just-mounted auth-method's bao-side accessor onto status. Called
// after a successful enable / tune so the next reconcile (and any
// downstream CRs) can use the accessor without re-listing.
func accessorMutator(ctx context.Context, bao baoclient.Client, path string, ns baoclient.CallOption) resource.StatusMutator[*v1alpha1.OpenBaoAuthMethod] {
	cur, err := bao.GetAuthMethod(ctx, path, ns)
	if err != nil || cur == nil || cur.Accessor == "" {
		return nil
	}
	accessor := cur.Accessor
	return func(c *v1alpha1.OpenBaoAuthMethod) {
		c.Status.MountAccessor = accessor
	}
}

// checkAuthMethodCollision returns ErrNameCollision when another
// OpenBaoAuthMethod CR (different UID) targets the same
// (OpenBaoNamespace, path) tuple. Two CRs in different bao namespaces
// don't collide because bao isolates them via X-Vault-Namespace.
func checkAuthMethodCollision(ctx context.Context, cl client.Client, m *v1alpha1.OpenBaoAuthMethod) error {
	var all v1alpha1.OpenBaoAuthMethodList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoAuthMethods for collision check: %v",
			resource.ErrInternal, err)
	}
	targetPath := m.BaoPath()
	targetNS := m.OpenBaoNamespace()
	mineKey := m.Namespace + "/" + m.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == m.UID {
			continue
		}
		if other.BaoPath() != targetPath {
			continue
		}
		if other.OpenBaoNamespace() != targetNS {
			continue
		}
		var otherWins bool
		switch {
		case other.CreationTimestamp.Before(&m.CreationTimestamp):
			otherWins = true
		case m.CreationTimestamp.Before(&other.CreationTimestamp):
			otherWins = false
		default:
			otherKey := other.Namespace + "/" + other.Name
			otherWins = otherKey < mineKey
		}
		if otherWins {
			return fmt.Errorf("%w: bao auth mount %q (ns=%q) already owned by OpenBaoAuthMethod %s/%s",
				resource.ErrNameCollision, targetPath, targetNS, other.Namespace, other.Name)
		}
	}
	return nil
}

func (r *OpenBaoAuthMethodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoAuthMethod{}).
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
		return nil, fmt.Errorf("set VAULT_ADDR/VAULT_TOKEN (or BAO_ADDR/BAO_TOKEN) for OpenBaoAuthMethodReconciler")
	}
	return baoclient.NewHTTPClient(addr, token)
}
