package openbaojwtoidcauthengineconfig

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
	"github.com/stakater/openbao-config-operator/internal/hmacstore"
	"github.com/stakater/openbao-config-operator/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaojwtoidcauthengineconfigs,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaojwtoidcauthengineconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaojwtoidcauthengineconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

const OpenBaoJWTOIDCAuthEngineConfigFinalizer = "openbaojwtoidcauthengineconfig.security.mto.stakater.com/finalizer"

type OpenBaoJWTOIDCAuthEngineConfigReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoJWTOIDCAuthEngineConfig]
	cl client.Client
}

func NewOpenBaoJWTOIDCAuthEngineConfigReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client, hmac hmacstore.Computer) *OpenBaoJWTOIDCAuthEngineConfigReconciler {
	return &OpenBaoJWTOIDCAuthEngineConfigReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoJWTOIDCAuthEngineConfig](mgr, OpenBaoJWTOIDCAuthEngineConfigFinalizer,
			OpenBaoJWTOIDCAuthEngineConfigHandlers(mgr.GetClient(), bao, hmac)),
		cl: mgr.GetClient(),
	}
}

func OpenBaoJWTOIDCAuthEngineConfigHandlers(cl client.Client, bao baoclient.Client, hmac hmacstore.Computer) resource.Handlers[*v1alpha1.OpenBaoJWTOIDCAuthEngineConfig] {
	return resource.Handlers[*v1alpha1.OpenBaoJWTOIDCAuthEngineConfig]{
		NewInstance: func() *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig {
			return &v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{}
		},

		BaoGet: func(ctx context.Context, c *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig) (map[string]any, error) {
			ns := baoclient.WithNamespace(c.OpenBaoNamespace())
			cur, err := bao.ReadJWTOIDCConfig(ctx, c.Spec.Path, ns)
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"config":               cur,
				"currentSecretMAC":     hmac.Compute(c.SecretMACInputs()...),
				"lastWrittenSecretMAC": c.Status.LastWrittenSecretMAC,
			}, nil
		},

		BaoWrite: func(ctx context.Context, c *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig) (resource.StatusMutator[*v1alpha1.OpenBaoJWTOIDCAuthEngineConfig], error) {
			if err := checkConfigCollision(ctx, cl, c); err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(c.OpenBaoNamespace())
			if err := bao.WriteJWTOIDCConfig(ctx, c.Spec.Path, c.ToBaoSpec(), ns); err != nil {
				return nil, err
			}
			mac := hmac.Compute(c.SecretMACInputs()...)
			return func(t *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig) {
				t.Status.LastWrittenSecretMAC = mac
			}, nil
		},

		// IsDeletable=false; bao has no DELETE on /config.
		BaoDelete: func(ctx context.Context, _ *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig) error {
			return nil
		},
		// Rename hook is intentionally empty: bao has no DELETE on
		// auth/<mount>/config, and the previous mount itself is owned
		// by OpenBaoAuthMethod (not this CR). When that mount is later
		// disabled via its OpenBaoAuthMethod, bao discards the config
		// along with it. So a rename across spec.path leaves no
		// orphan this CR is responsible for cleaning up.
		BaoDeleteIdentity: func(ctx context.Context, _ *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig, _, _ string) error {
			return nil
		},

		CheckCollision: func(ctx context.Context, c *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig) error {
			return checkConfigCollision(ctx, cl, c)
		},
	}
}

func checkConfigCollision(ctx context.Context, cl client.Client, c *v1alpha1.OpenBaoJWTOIDCAuthEngineConfig) error {
	var all v1alpha1.OpenBaoJWTOIDCAuthEngineConfigList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoJWTOIDCAuthEngineConfigs for collision check: %v",
			resource.ErrInternal, err)
	}
	targetPath := c.BaoName()
	targetNS := c.OpenBaoNamespace()
	mineKey := c.Namespace + "/" + c.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == c.UID {
			continue
		}
		if other.BaoName() != targetPath {
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
			return fmt.Errorf("%w: bao jwt/oidc auth config at %q (ns=%q) already owned by OpenBaoJWTOIDCAuthEngineConfig %s/%s",
				resource.ErrNameCollision, targetPath, targetNS, other.Namespace, other.Name)
		}
	}
	return nil
}

// SetupWithManager wires the controller. Watches the Secret holding
// the OIDC client_secret so a rotation re-enqueues the config CR and
// the next reconcile picks up the new value.
func (r *OpenBaoJWTOIDCAuthEngineConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoJWTOIDCAuthEngineConfig{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// No GenerationChangedPredicate on the Secret watch — Secret
		// data changes don't bump metadata.generation, so gating on
		// generation would silently drop every rotation event.
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.configsReferencingSecret),
		).
		Complete(r)
}

func (r *OpenBaoJWTOIDCAuthEngineConfigReconciler) configsReferencingSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	sec, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}
	var configs v1alpha1.OpenBaoJWTOIDCAuthEngineConfigList
	if err := r.cl.List(ctx, &configs); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range configs.Items {
		c := &configs.Items[i]
		if c.Spec.OIDCClientSecretRef == nil {
			continue
		}
		refNS := c.Spec.OIDCClientSecretRef.Namespace
		if refNS == "" {
			refNS = c.Namespace
		}
		if refNS == sec.Namespace && c.Spec.OIDCClientSecretRef.Name == sec.Name {
			out = append(out, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: c.Namespace, Name: c.Name},
			})
		}
	}
	return out
}
