package openbaosecretengine

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

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaosecretengines,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaosecretengines/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaosecretengines/finalizers,verbs=update

// OpenBaoSecretEngineFinalizer follows the Kubernetes convention
// <resource>.<group>/finalizer.
const OpenBaoSecretEngineFinalizer = "openbaosecretengine.security.mto.stakater.com/finalizer"

type OpenBaoSecretEngineReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoSecretEngine]
}

// NewOpenBaoSecretEngineReconcilerWithClient is the test-friendly constructor.
func NewOpenBaoSecretEngineReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoSecretEngineReconciler {
	return &OpenBaoSecretEngineReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoSecretEngine](mgr, OpenBaoSecretEngineFinalizer,
			OpenBaoSecretEngineHandlers(mgr.GetClient(), bao)),
	}
}

// OpenBaoSecretEngineHandlers builds the bao-I/O callbacks. Every bao
// call carries spec.openbaoNamespace as the X-Vault-Namespace header
// via baoclient.WithNamespace; empty (the default) targets root.
func OpenBaoSecretEngineHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoSecretEngine] {
	return resource.Handlers[*v1alpha1.OpenBaoSecretEngine]{
		NewInstance: func() *v1alpha1.OpenBaoSecretEngine { return &v1alpha1.OpenBaoSecretEngine{} },

		BaoGet: func(ctx context.Context, m *v1alpha1.OpenBaoSecretEngine) (map[string]any, error) {
			if _, ok := m.EngineType(); !ok {
				// IsValid catches this case for new CRs; defense in depth
				// for stale objects in etcd whose spec was relaxed before
				// the CRD was tightened.
				return nil, fmt.Errorf("%w: spec selects no engine type", resource.ErrInternal)
			}
			ns := baoclient.WithNamespace(m.OpenBaoNamespace())
			mount, err := bao.GetSecretEngineMount(ctx, m.Spec.Path, ns)
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"description": mount.Description,
				"options":     mount.Options,
			}, nil
		},

		BaoWrite: func(ctx context.Context, m *v1alpha1.OpenBaoSecretEngine) (resource.StatusMutator[*v1alpha1.OpenBaoSecretEngine], error) {
			if err := checkSecretEnginePathCollision(ctx, cl, m); err != nil {
				return nil, err
			}
			baoType, ok := m.EngineType()
			if !ok {
				return nil, fmt.Errorf("%w: spec selects no engine type", resource.ErrInternal)
			}
			ns := baoclient.WithNamespace(m.OpenBaoNamespace())
			spec := baoclient.SecretEngineMountSpec{
				Type:        baoType,
				Description: m.Spec.Description,
			}
			if m.Spec.KvV2 != nil {
				spec.Options = map[string]string{"version": "2"}
			}
			// Bao's enable endpoint creates but does not update — it
			// returns 400 "path already in use" on a re-call (which the
			// wrapper converts to a no-op). To support description /
			// options updates, the controller probes for an existing
			// mount and calls tune instead of enable on the update
			// path. The probe is cheap (single LIST) and avoids a
			// state machine in the type.
			//
			// Engine-type immutability: if the existing mount has a
			// different type than the spec selects (e.g. user edited
			// kvV2 → transit on a CR backed by a kv mount), bao
			// rejects every "fix" — type cannot change in-place.
			// Detect and surface a clear error instead of letting the
			// drift loop try forever.
			existing, err := bao.GetSecretEngineMount(ctx, m.Spec.Path, ns)
			switch {
			case err == nil && existing.Type != baoType:
				return nil, fmt.Errorf("%w: bao mount %q has type %q, spec selects %q — "+
					"engine type is immutable; delete the CR (and the bao mount) and recreate",
					resource.ErrInternal, m.Spec.Path, existing.Type, baoType)
			case err == nil:
				return nil, bao.TuneSecretEngine(ctx, m.Spec.Path, spec, ns)
			case errors.Is(err, baoclient.ErrNotFound):
				return nil, bao.EnableSecretEngine(ctx, m.Spec.Path, spec, ns)
			default:
				return nil, err
			}
		},

		BaoDelete: func(ctx context.Context, m *v1alpha1.OpenBaoSecretEngine) error {
			if _, ok := m.EngineType(); !ok {
				// Spec was invalid; no bao write ever happened, so
				// nothing to delete. status.baoWritten gates this path
				// at the base level, so reaching here without a type
				// means the CR never wrote.
				return nil
			}
			ns := baoclient.WithNamespace(m.OpenBaoNamespace())
			return bao.DisableSecretEngineMount(ctx, m.Spec.Path, ns)
		},

		BaoDeleteIdentity: func(ctx context.Context, _ *v1alpha1.OpenBaoSecretEngine, name, namespace string) error {
			// Rename cleanup. The previous identity is always a secret-
			// engine mount because this CRD only manages those — no kind
			// dimension to disambiguate.
			ns := baoclient.WithNamespace(namespace)
			return bao.DisableSecretEngineMount(ctx, name, ns)
		},

		CheckCollision: func(ctx context.Context, m *v1alpha1.OpenBaoSecretEngine) error {
			return checkSecretEnginePathCollision(ctx, cl, m)
		},
	}
}

// checkSecretEnginePathCollision returns ErrNameCollision when another
// OpenBaoSecretEngine CR (different UID) targets the same bao endpoint —
// matching tuple is (OpenBaoNamespace, path). Two CRs in different
// OpenBao namespaces do not collide because bao isolates them via
// X-Vault-Namespace.
//
// Tie-break: older CreationTimestamp wins; on tie, lex order of
// <namespace>/<name> wins. Mirrors the Policy / KAER collision logic.
func checkSecretEnginePathCollision(ctx context.Context, cl client.Client, m *v1alpha1.OpenBaoSecretEngine) error {
	var all v1alpha1.OpenBaoSecretEngineList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoSecretEngines for collision check: %v",
			resource.ErrInternal, err)
	}
	if _, ok := m.EngineType(); !ok {
		return nil
	}
	targetPath := m.BaoPath()
	targetNS := m.OpenBaoNamespace()
	mineKey := m.Namespace + "/" + m.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == m.UID {
			continue
		}
		if _, otherOK := other.EngineType(); !otherOK {
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
			return fmt.Errorf("%w: bao secret-engine mount %q (ns=%q) already owned by OpenBaoSecretEngine %s/%s",
				resource.ErrNameCollision, targetPath, targetNS, other.Namespace, other.Name)
		}
	}
	return nil
}

// SetupWithManager registers the controller with a
// GenerationChangedPredicate so status writes do not trigger
// re-reconciles.
func (r *OpenBaoSecretEngineReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoSecretEngine{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
