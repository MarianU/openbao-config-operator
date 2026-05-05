package openbaocertauthengineconfig

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

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaocertauthengineconfigs,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaocertauthengineconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaocertauthengineconfigs/finalizers,verbs=update

const OpenBaoCertAuthEngineConfigFinalizer = "openbaocertauthengineconfig.security.mto.stakater.com/finalizer"

type OpenBaoCertAuthEngineConfigReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoCertAuthEngineConfig]
}

func NewOpenBaoCertAuthEngineConfigReconciler(mgr ctrl.Manager) (*OpenBaoCertAuthEngineConfigReconciler, error) {
	bao, err := newBaoFromEnv()
	if err != nil {
		return nil, err
	}
	return NewOpenBaoCertAuthEngineConfigReconcilerWithClient(mgr, bao), nil
}

func NewOpenBaoCertAuthEngineConfigReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoCertAuthEngineConfigReconciler {
	return &OpenBaoCertAuthEngineConfigReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoCertAuthEngineConfig](mgr, OpenBaoCertAuthEngineConfigFinalizer,
			OpenBaoCertAuthEngineConfigHandlers(mgr.GetClient(), bao)),
	}
}

func OpenBaoCertAuthEngineConfigHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoCertAuthEngineConfig] {
	return resource.Handlers[*v1alpha1.OpenBaoCertAuthEngineConfig]{
		NewInstance: func() *v1alpha1.OpenBaoCertAuthEngineConfig {
			return &v1alpha1.OpenBaoCertAuthEngineConfig{}
		},

		BaoGet: func(ctx context.Context, c *v1alpha1.OpenBaoCertAuthEngineConfig) (map[string]any, error) {
			ns := baoclient.WithNamespace(c.OpenBaoNamespace())
			cur, err := bao.ReadCertAuthConfig(ctx, c.Spec.Path, ns)
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{"config": cur}, nil
		},

		BaoWrite: func(ctx context.Context, c *v1alpha1.OpenBaoCertAuthEngineConfig) (resource.StatusMutator[*v1alpha1.OpenBaoCertAuthEngineConfig], error) {
			if err := checkConfigCollision(ctx, cl, c); err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(c.OpenBaoNamespace())
			return nil, bao.WriteCertAuthConfig(ctx, c.Spec.Path, c.ToBaoSpec(), ns)
		},

		// IsDeletable=false on this CRD — bao has no DELETE on
		// auth/<mount>/config. The shared base's deletion path
		// releases the finalizer without calling BaoDelete, but
		// the handler still needs to be defined to satisfy the
		// interface (not invoked in practice).
		BaoDelete: func(ctx context.Context, _ *v1alpha1.OpenBaoCertAuthEngineConfig) error {
			return nil
		},

		BaoDeleteIdentity: func(ctx context.Context, _ *v1alpha1.OpenBaoCertAuthEngineConfig, _, _ string) error {
			return nil
		},

		CheckCollision: func(ctx context.Context, c *v1alpha1.OpenBaoCertAuthEngineConfig) error {
			return checkConfigCollision(ctx, cl, c)
		},
	}
}

// checkConfigCollision returns ErrNameCollision when another CR
// (different UID) targets the same (mount path, openbaoNamespace) tuple.
func checkConfigCollision(ctx context.Context, cl client.Client, c *v1alpha1.OpenBaoCertAuthEngineConfig) error {
	var all v1alpha1.OpenBaoCertAuthEngineConfigList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoCertAuthEngineConfigs for collision check: %v",
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
			return fmt.Errorf("%w: bao cert auth config at %q (ns=%q) already owned by OpenBaoCertAuthEngineConfig %s/%s",
				resource.ErrNameCollision, targetPath, targetNS, other.Namespace, other.Name)
		}
	}
	return nil
}

func (r *OpenBaoCertAuthEngineConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoCertAuthEngineConfig{}).
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
		return nil, fmt.Errorf("set VAULT_ADDR/VAULT_TOKEN (or BAO_ADDR/BAO_TOKEN) for OpenBaoCertAuthEngineConfigReconciler")
	}
	return baoclient.NewHTTPClient(addr, token)
}
