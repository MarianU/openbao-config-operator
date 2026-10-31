package openbaodatabaseengineconfig

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaodatabaseengineconfigs,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaodatabaseengineconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaodatabaseengineconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

const OpenBaoDatabaseEngineConfigFinalizer = "openbaodatabaseengineconfig.security.mto.stakater.com/finalizer"

type OpenBaoDatabaseEngineConfigReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoDatabaseEngineConfig]
	cl client.Client
}

func NewOpenBaoDatabaseEngineConfigReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoDatabaseEngineConfigReconciler {
	return &OpenBaoDatabaseEngineConfigReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoDatabaseEngineConfig](mgr, OpenBaoDatabaseEngineConfigFinalizer,
			OpenBaoDatabaseEngineConfigHandlers(mgr.GetClient(), bao)),
		cl: mgr.GetClient(),
	}
}

func OpenBaoDatabaseEngineConfigHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoDatabaseEngineConfig] {
	return resource.Handlers[*v1alpha1.OpenBaoDatabaseEngineConfig]{
		NewInstance: func() *v1alpha1.OpenBaoDatabaseEngineConfig {
			return &v1alpha1.OpenBaoDatabaseEngineConfig{}
		},

		BaoGet: func(ctx context.Context, c *v1alpha1.OpenBaoDatabaseEngineConfig) (map[string]any, error) {
			cur, err := bao.ReadDatabaseConnection(ctx, c.Mount(), c.BaoName(),
				baoclient.WithNamespace(c.OpenBaoNamespace()))
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{"config": cur}, nil
		},

		BaoWrite: func(ctx context.Context, c *v1alpha1.OpenBaoDatabaseEngineConfig) (resource.StatusMutator[*v1alpha1.OpenBaoDatabaseEngineConfig], error) {
			if err := checkCollision(ctx, cl, c); err != nil {
				return nil, err
			}
			// Resolve the credential pair in-memory from the referenced Secret;
			// it is never persisted to the CR. CredentialRef existence has
			// already been validated in PrepareInternalValues.
			user, pass, err := c.ResolvedCredentials(ctx, cl)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", resource.ErrInternal, err)
			}
			spec := c.ToConnectionConfig()
			spec.Username = user
			spec.Password = pass
			if err := bao.WriteDatabaseConnection(ctx, c.Mount(), c.BaoName(), spec,
				baoclient.WithNamespace(c.OpenBaoNamespace())); err != nil {
				return nil, err
			}
			// Stamp the bao mount so a simultaneous spec.mount + spec.name
			// edit cleans up the previous connection at its real location.
			mountSnapshot := c.Mount()
			return func(cur *v1alpha1.OpenBaoDatabaseEngineConfig) {
				cur.Status.LastWrittenMount = mountSnapshot
			}, nil
		},

		BaoDelete: func(ctx context.Context, c *v1alpha1.OpenBaoDatabaseEngineConfig) error {
			return bao.DeleteDatabaseConnection(ctx, c.Mount(), c.BaoName(),
				baoclient.WithNamespace(c.OpenBaoNamespace()))
		},

		BaoDeleteIdentity: func(ctx context.Context, c *v1alpha1.OpenBaoDatabaseEngineConfig, name, namespace string) error {
			mount := c.Status.LastWrittenMount
			if mount == "" {
				mount = c.Mount()
			}
			return bao.DeleteDatabaseConnection(ctx, mount, name,
				baoclient.WithNamespace(namespace))
		},

		CheckCollision: func(ctx context.Context, c *v1alpha1.OpenBaoDatabaseEngineConfig) error {
			return checkCollision(ctx, cl, c)
		},
	}
}

// checkCollision returns ErrNameCollision when another CR (different UID)
// targets the same (openbaoNamespace, mount, connection name) tuple. Two CRs
// at the same name on different mounts don't collide (different bao path).
func checkCollision(ctx context.Context, cl client.Client, c *v1alpha1.OpenBaoDatabaseEngineConfig) error {
	var all v1alpha1.OpenBaoDatabaseEngineConfigList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoDatabaseEngineConfigs for collision check: %v",
			resource.ErrInternal, err)
	}
	targetMount := c.Mount()
	targetName := c.BaoName()
	targetNS := c.OpenBaoNamespace()
	mineKey := c.Namespace + "/" + c.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == c.UID {
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
		case other.CreationTimestamp.Before(&c.CreationTimestamp):
			otherWins = true
		case c.CreationTimestamp.Before(&other.CreationTimestamp):
			otherWins = false
		default:
			otherKey := other.Namespace + "/" + other.Name
			otherWins = otherKey < mineKey
		}
		if otherWins {
			return fmt.Errorf("%w: database connection %q (mount=%q, ns=%q) already owned by OpenBaoDatabaseEngineConfig %s/%s",
				resource.ErrNameCollision, targetName, targetMount, targetNS,
				other.Namespace, other.Name)
		}
	}
	return nil
}

// SetupWithManager wires the controller and watches the Secrets that supply
// the connection credentials. A Secret rotation re-enqueues every
// OpenBaoDatabaseEngineConfig whose spec.credentialsRef points at that
// Secret, so the next reconcile picks up the new credential pair.
func (r *OpenBaoDatabaseEngineConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoDatabaseEngineConfig{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.configsReferencingSecret),
		).
		Complete(r)
}

func (r *OpenBaoDatabaseEngineConfigReconciler) configsReferencingSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	sec, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}
	var configs v1alpha1.OpenBaoDatabaseEngineConfigList
	if err := r.cl.List(ctx, &configs); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range configs.Items {
		cfg := &configs.Items[i]
		if cfg.Spec.CredentialsRef == nil {
			continue
		}
		refNS := cfg.Spec.CredentialsRef.Namespace
		if refNS == "" {
			refNS = cfg.Namespace
		}
		if refNS == sec.Namespace && cfg.Spec.CredentialsRef.Name == sec.Name {
			out = append(out, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: cfg.Namespace, Name: cfg.Name},
			})
		}
	}
	return out
}
