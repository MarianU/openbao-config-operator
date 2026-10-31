package openbaogeneratedsecret

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1alpha1 "github.com/stakater/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaogeneratedsecrets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaogeneratedsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaogeneratedsecrets/finalizers,verbs=update

const OpenBaoGeneratedSecretFinalizer = "openbaogeneratedsecret.security.mto.stakater.com/finalizer"

type OpenBaoGeneratedSecretReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoGeneratedSecret]
}

func NewOpenBaoGeneratedSecretReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoGeneratedSecretReconciler {
	return &OpenBaoGeneratedSecretReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoGeneratedSecret](
			mgr, OpenBaoGeneratedSecretFinalizer, OpenBaoGeneratedSecretHandlers(mgr.GetClient(), bao)),
	}
}

func OpenBaoGeneratedSecretHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoGeneratedSecret] {
	return resource.Handlers[*v1alpha1.OpenBaoGeneratedSecret]{
		NewInstance: func() *v1alpha1.OpenBaoGeneratedSecret {
			return &v1alpha1.OpenBaoGeneratedSecret{}
		},

		BaoGet: func(ctx context.Context, p *v1alpha1.OpenBaoGeneratedSecret) (map[string]any, error) {
			ns := baoclient.WithNamespace(p.OpenBaoNamespace())
			kv, err := bao.ReadKVSecret(ctx, p.KVMount(), p.BaoName(), ns)
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{"data": kv.Data}, nil
		},

		BaoWrite: func(ctx context.Context, p *v1alpha1.OpenBaoGeneratedSecret) (resource.StatusMutator[*v1alpha1.OpenBaoGeneratedSecret], error) {
			if err := checkGeneratedSecretCollision(ctx, cl, p); err != nil {
				return nil, err
			}
			val, err := p.Generate()
			if err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(p.OpenBaoNamespace())
			data := map[string]string{p.Key(): val}
			version, err := bao.WriteKVSecret(ctx, p.KVMount(), p.BaoName(), data, ns)
			if err != nil {
				return nil, err
			}
			// Capture rotation time at write time so the next rotation is
			// scheduled from when the value actually landed in bao.
			writtenAt := time.Now()
			mountSnapshot := p.KVMount()
			token := strings.TrimSpace(p.Annotations[v1alpha1.RotationAnnotationKey])
			return func(cur *v1alpha1.OpenBaoGeneratedSecret) {
				if token != "" {
					// Idempotency: the same annotation token must not rotate again.
					cur.Status.LastRequestedRotation = token
				}
				cur.MarkWritten(mountSnapshot, version, writtenAt)
			}, nil
		},

		BaoDelete: func(ctx context.Context, p *v1alpha1.OpenBaoGeneratedSecret) error {
			ns := baoclient.WithNamespace(p.OpenBaoNamespace())
			return bao.DeleteKVSecret(ctx, p.KVMount(), p.BaoName(), ns)
		},

		BaoDeleteIdentity: func(ctx context.Context, p *v1alpha1.OpenBaoGeneratedSecret, name, namespace string) error {
			mount := p.Status.LastWrittenMount
			if mount == "" {
				mount = p.KVMount()
			}
			return bao.DeleteKVSecret(ctx, mount, name, baoclient.WithNamespace(namespace))
		},

		CheckCollision: func(ctx context.Context, p *v1alpha1.OpenBaoGeneratedSecret) error {
			return checkGeneratedSecretCollision(ctx, cl, p)
		},
	}
}

// checkGeneratedSecretCollision returns ErrNameCollision when another
// OpenBaoGeneratedSecret CR (different UID) targets the same
// (openbaoNamespace, mount, data path) tuple.
func checkGeneratedSecretCollision(ctx context.Context, cl client.Client, p *v1alpha1.OpenBaoGeneratedSecret) error {
	var all v1alpha1.OpenBaoGeneratedSecretList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoGeneratedSecrets for collision check: %v",
			resource.ErrInternal, err)
	}
	targetMount := p.KVMount()
	targetPath := strings.Trim(p.BaoName(), "/")
	targetNS := p.OpenBaoNamespace()
	mineKey := p.Namespace + "/" + p.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == p.UID {
			continue
		}
		if other.KVMount() != targetMount {
			continue
		}
		if strings.Trim(other.BaoName(), "/") != targetPath {
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
			return fmt.Errorf("%w: generated secret %q (mount=%q, ns=%q) already owned by OpenBaoGeneratedSecret %s/%s",
				resource.ErrNameCollision, targetPath, targetMount, targetNS, other.Namespace, other.Name)
		}
	}
	return nil
}

func (r *OpenBaoGeneratedSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoGeneratedSecret{}).
		Named("openbaogeneratedsecret").
		// Reconcile on spec changes (generation) AND on annotation-only
		// changes so an on-demand rotation request is picked up near-
		// immediately rather than waiting for the periodic requeue.
		WithEventFilter(predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.AnnotationChangedPredicate{},
		)).
		Complete(r)
}
