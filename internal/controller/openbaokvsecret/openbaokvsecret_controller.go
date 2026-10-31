package openbaokvsecret

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaokvsecrets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaokvsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaokvsecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch

const OpenBaoKvSecretFinalizer = "openbaokvsecret.security.mto.stakater.com/finalizer"

// sourceData resolves the Kubernetes Secret named by spec.sourceSecret in the
// CR's namespace. It optionally creates an EMPTY placeholder Secret when the
// named Secret does not exist (spec.ensureSecret), so the CR can anchor a
// Secret that real values are filled into later. It never reads or stages
// secret material in the CR or in Git — the desired data is the live Secret's
// data, copied straight through.
func sourceData(ctx context.Context, cl client.Client, p *v1alpha1.OpenBaoKvSecret) (map[string]string, error) {
	key := client.ObjectKey{Namespace: p.Namespace, Name: p.Spec.SourceSecret}
	var sec corev1.Secret
	err := cl.Get(ctx, key, &sec)
	if err == nil {
		return secretStringData(sec.Data), nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("%w: getting source Secret %q: %v",
			resource.ErrInternal, key.Name, err)
	}
	if !p.Spec.EnsureSecret {
		return nil, fmt.Errorf("%w: source Secret %q not found in namespace %q",
			resource.ErrInternal, key.Name, p.Namespace)
	}
	// Anchor an empty Secret so a fill-in-later bootstrap can target it.
	empty := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: p.Namespace},
		Data:       map[string][]byte{},
	}
	if err := cl.Create(ctx, empty); err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("%w: creating empty source Secret %q: %v",
			resource.ErrInternal, key.Name, err)
	}
	return nil, nil
}

// secretStringData converts a Secret's binary data map to string values for
// the bao wire (KVv2 values are strings).
func secretStringData(data map[string][]byte) map[string]string {
	if len(data) == 0 {
		return nil
	}
	out := make(map[string]string, len(data))
	for k, v := range data {
		out[k] = string(v)
	}
	return out
}

type OpenBaoKvSecretReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoKvSecret]
	cl client.Client
}

func NewOpenBaoKvSecretReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoKvSecretReconciler {
	return &OpenBaoKvSecretReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoKvSecret](
			mgr, OpenBaoKvSecretFinalizer, OpenBaoKvSecretHandlers(mgr.GetClient(), bao)),
		cl: mgr.GetClient(),
	}
}

func OpenBaoKvSecretHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoKvSecret] {
	return resource.Handlers[*v1alpha1.OpenBaoKvSecret]{
		NewInstance: func() *v1alpha1.OpenBaoKvSecret {
			return &v1alpha1.OpenBaoKvSecret{}
		},

		BaoGet: func(ctx context.Context, p *v1alpha1.OpenBaoKvSecret) (map[string]any, error) {
			// Resolve + (optionally) ensure the source Secret first so a
			// missing-source error surfaces here instead of mid-write.
			desired, err := sourceData(ctx, cl, p)
			if err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(p.OpenBaoNamespace())
			kv, err := bao.ReadKVSecret(ctx, p.KVMount(), p.BaoName(), ns)
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			// Pass the source data under "desired" so the type's drift
			// comparator compares bao current vs the live Secret, not vs
			// anything held in the CR.
			return map[string]any{"data": kv.Data, "desired": desired}, nil
		},

		BaoWrite: func(ctx context.Context, p *v1alpha1.OpenBaoKvSecret) (resource.StatusMutator[*v1alpha1.OpenBaoKvSecret], error) {
			if err := checkKvSecretCollision(ctx, cl, p); err != nil {
				return nil, err
			}
			data, err := sourceData(ctx, cl, p)
			if err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(p.OpenBaoNamespace())
			if len(data) == 0 {
				// Source Secret has no keys (e.g. freshly created empty
				// anchor). Keep bao in sync by removing any stale entry —
				// KVv2 has no meaningful "empty" write.
				if err := bao.DeleteKVSecret(ctx, p.KVMount(), p.BaoName(), ns); err != nil {
					return nil, err
				}
				return nil, nil
			}
			version, err := bao.WriteKVSecret(ctx, p.KVMount(), p.BaoName(), data, ns)
			if err != nil {
				return nil, err
			}
			mountSnapshot := p.KVMount()
			// Stamp the mount path + version on status so a subsequent
			// rename that also moves the secret to a new mount can clean
			// up the previous (mount, path) tuple via BaoDeleteIdentity.
			return func(cur *v1alpha1.OpenBaoKvSecret) {
				cur.MarkWritten(mountSnapshot, version)
			}, nil
		},

		BaoDelete: func(ctx context.Context, p *v1alpha1.OpenBaoKvSecret) error {
			ns := baoclient.WithNamespace(p.OpenBaoNamespace())
			return bao.DeleteKVSecret(ctx, p.KVMount(), p.BaoName(), ns)
		},

		BaoDeleteIdentity: func(ctx context.Context, p *v1alpha1.OpenBaoKvSecret, name, namespace string) error {
			// Use the KVv2 mount that was active when (name, namespace)
			// was last written, NOT the current spec.mount. A spec edit that
			// changes both path AND mount in one go would otherwise target
			// the new mount and silently 404, orphaning the secret at the
			// old (mount, path).
			mount := p.Status.LastWrittenMount
			if mount == "" {
				mount = p.KVMount()
			}
			return bao.DeleteKVSecret(ctx, mount, name, baoclient.WithNamespace(namespace))
		},

		CheckCollision: func(ctx context.Context, p *v1alpha1.OpenBaoKvSecret) error {
			return checkKvSecretCollision(ctx, cl, p)
		},
	}
}

// checkKvSecretCollision returns ErrNameCollision when another
// OpenBaoKvSecret CR (different UID) targets the same
// (openbaoNamespace, mount, data path) tuple. Two CRs at the same path on
// different mounts don't collide because the bao path differs.
func checkKvSecretCollision(ctx context.Context, cl client.Client, p *v1alpha1.OpenBaoKvSecret) error {
	var all v1alpha1.OpenBaoKvSecretList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoKvSecrets for collision check: %v",
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
			return fmt.Errorf("%w: KV secret %q (mount=%q, ns=%q) already owned by OpenBaoKvSecret %s/%s",
				resource.ErrNameCollision, targetPath, targetMount, targetNS, other.Namespace, other.Name)
		}
	}
	return nil
}

// SetupWithManager wires the controller and watches the source Secrets that
// feed the bao mirror. A source Secret change re-enqueues every
// OpenBaoKvSecret CR whose spec.sourceSecret points at that Secret, so the
// next reconcile pushes the new data into bao.
func (r *OpenBaoKvSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoKvSecret{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("openbaokvsecret").
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.secretsReferencingCR),
		).
		Complete(r)
}

func (r *OpenBaoKvSecretReconciler) secretsReferencingCR(ctx context.Context, obj client.Object) []reconcile.Request {
	sec, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}
	var all v1alpha1.OpenBaoKvSecretList
	if err := r.cl.List(ctx, &all); err != nil {
		return nil
	}
	out := make([]reconcile.Request, 0, len(all.Items))
	for i := range all.Items {
		p := &all.Items[i]
		if p.Spec.SourceSecret == "" || p.Spec.SourceSecret != sec.Name || p.Namespace != sec.Namespace {
			continue
		}
		out = append(out, reconcile.Request{
			NamespacedName: types.NamespacedName{Namespace: p.Namespace, Name: p.Name},
		})
	}
	return out
}
