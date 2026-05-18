package openbaokubernetesauthengineconfig

import (
	"context"
	"errors"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/hmacstore"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaokubernetesauthengineconfigs,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaokubernetesauthengineconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaokubernetesauthengineconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update

const OpenBaoKubernetesAuthEngineConfigFinalizer = "openbaokubernetesauthengineconfig.security.mto.stakater.com/finalizer"

type OpenBaoKubernetesAuthEngineConfigReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoKubernetesAuthEngineConfig]
	cl client.Client
}

func NewOpenBaoKubernetesAuthEngineConfigReconciler(mgr ctrl.Manager, hmac hmacstore.Computer) (*OpenBaoKubernetesAuthEngineConfigReconciler, error) {
	bao, err := newBaoFromEnv()
	if err != nil {
		return nil, err
	}
	return NewOpenBaoKubernetesAuthEngineConfigReconcilerWithClient(mgr, bao, hmac), nil
}

func NewOpenBaoKubernetesAuthEngineConfigReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client, hmac hmacstore.Computer) *OpenBaoKubernetesAuthEngineConfigReconciler {
	return &OpenBaoKubernetesAuthEngineConfigReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoKubernetesAuthEngineConfig](mgr, OpenBaoKubernetesAuthEngineConfigFinalizer,
			OpenBaoKubernetesAuthEngineConfigHandlers(mgr.GetClient(), bao, hmac)),
		cl: mgr.GetClient(),
	}
}

func OpenBaoKubernetesAuthEngineConfigHandlers(cl client.Client, bao baoclient.Client, hmac hmacstore.Computer) resource.Handlers[*v1alpha1.OpenBaoKubernetesAuthEngineConfig] {
	return resource.Handlers[*v1alpha1.OpenBaoKubernetesAuthEngineConfig]{
		NewInstance: func() *v1alpha1.OpenBaoKubernetesAuthEngineConfig {
			return &v1alpha1.OpenBaoKubernetesAuthEngineConfig{}
		},

		BaoGet: func(ctx context.Context, c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) (map[string]any, error) {
			ns := baoclient.WithNamespace(c.OpenBaoNamespace())
			cur, err := bao.ReadK8sAuthConfig(ctx, c.Spec.Path, ns)
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

		BaoWrite: func(ctx context.Context, c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) (resource.StatusMutator[*v1alpha1.OpenBaoKubernetesAuthEngineConfig], error) {
			if err := checkConfigCollision(ctx, cl, c); err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(c.OpenBaoNamespace())
			if err := bao.WriteK8sAuthConfig(ctx, c.Spec.Path, c.ToBaoSpec(), ns); err != nil {
				return nil, err
			}
			// Stamp the MAC of what we just wrote so the next reconcile
			// can recognise rotation.
			mac := hmac.Compute(c.SecretMACInputs()...)
			return func(t *v1alpha1.OpenBaoKubernetesAuthEngineConfig) {
				t.Status.LastWrittenSecretMAC = mac
			}, nil
		},

		// IsDeletable=false; bao has no DELETE on /config.
		BaoDelete: func(ctx context.Context, _ *v1alpha1.OpenBaoKubernetesAuthEngineConfig) error {
			return nil
		},
		// Rename hook is intentionally empty: bao has no DELETE on
		// auth/<mount>/config, and the previous mount itself is owned
		// by OpenBaoAuthMethod (not this CR). When that mount is later
		// disabled via its OpenBaoAuthMethod, bao discards the config
		// along with it. So a rename across spec.path leaves no
		// orphan this CR is responsible for cleaning up.
		BaoDeleteIdentity: func(ctx context.Context, _ *v1alpha1.OpenBaoKubernetesAuthEngineConfig, _, _ string) error {
			return nil
		},

		CheckCollision: func(ctx context.Context, c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) error {
			return checkConfigCollision(ctx, cl, c)
		},
	}
}

func checkConfigCollision(ctx context.Context, cl client.Client, c *v1alpha1.OpenBaoKubernetesAuthEngineConfig) error {
	var all v1alpha1.OpenBaoKubernetesAuthEngineConfigList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoKubernetesAuthEngineConfigs for collision check: %v",
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
			return fmt.Errorf("%w: bao kubernetes auth config at %q (ns=%q) already owned by OpenBaoKubernetesAuthEngineConfig %s/%s",
				resource.ErrNameCollision, targetPath, targetNS, other.Namespace, other.Name)
		}
	}
	return nil
}

// SetupWithManager wires the controller. Watches the Secret holding
// the token-reviewer JWT and the Secret holding the kubernetes CA cert,
// so a rotation of either re-enqueues the config CR.
func (r *OpenBaoKubernetesAuthEngineConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoKubernetesAuthEngineConfig{},
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

func (r *OpenBaoKubernetesAuthEngineConfigReconciler) configsReferencingSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	sec, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}
	var configs v1alpha1.OpenBaoKubernetesAuthEngineConfigList
	if err := r.cl.List(ctx, &configs); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range configs.Items {
		c := &configs.Items[i]
		if matchesSecretRef(c.Spec.TokenReviewerJwtRef, c.Namespace, sec) ||
			matchesCASecretRef(c.Spec.KubernetesCaCertRef, c.Namespace, sec) {
			out = append(out, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: c.Namespace, Name: c.Name},
			})
		}
	}
	return out
}

func matchesSecretRef(ref *v1alpha1.KubernetesTokenReviewerSecretRef, defaultNS string, sec *corev1.Secret) bool {
	if ref == nil {
		return false
	}
	ns := ref.Namespace
	if ns == "" {
		ns = defaultNS
	}
	return ns == sec.Namespace && ref.Name == sec.Name
}

func matchesCASecretRef(ref *v1alpha1.KubernetesCaSecretRef, defaultNS string, sec *corev1.Secret) bool {
	if ref == nil {
		return false
	}
	ns := ref.Namespace
	if ns == "" {
		ns = defaultNS
	}
	return ns == sec.Namespace && ref.Name == sec.Name
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
		return nil, fmt.Errorf("set VAULT_ADDR/VAULT_TOKEN (or BAO_ADDR/BAO_TOKEN) for OpenBaoKubernetesAuthEngineConfigReconciler")
	}
	return baoclient.NewHTTPClient(addr, token)
}
