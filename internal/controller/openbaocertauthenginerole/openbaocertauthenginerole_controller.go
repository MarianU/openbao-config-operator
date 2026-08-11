package openbaocertauthenginerole

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

	v1alpha1 "github.com/stakater-ab/openbao-config-operator/api/v1alpha1"
	baoclient "github.com/stakater-ab/openbao-config-operator/internal/client"
	"github.com/stakater-ab/openbao-config-operator/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaocertauthengineroles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaocertauthengineroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaocertauthengineroles/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

const OpenBaoCertAuthEngineRoleFinalizer = "openbaocertauthenginerole.security.mto.stakater.com/finalizer"

type OpenBaoCertAuthEngineRoleReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoCertAuthEngineRole]
	cl client.Client
}

func NewOpenBaoCertAuthEngineRoleReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoCertAuthEngineRoleReconciler {
	return &OpenBaoCertAuthEngineRoleReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoCertAuthEngineRole](mgr, OpenBaoCertAuthEngineRoleFinalizer,
			OpenBaoCertAuthEngineRoleHandlers(mgr.GetClient(), bao)),
		cl: mgr.GetClient(),
	}
}

func OpenBaoCertAuthEngineRoleHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoCertAuthEngineRole] {
	return resource.Handlers[*v1alpha1.OpenBaoCertAuthEngineRole]{
		NewInstance: func() *v1alpha1.OpenBaoCertAuthEngineRole {
			return &v1alpha1.OpenBaoCertAuthEngineRole{}
		},

		BaoGet: func(ctx context.Context, r *v1alpha1.OpenBaoCertAuthEngineRole) (map[string]any, error) {
			ns := baoclient.WithNamespace(r.OpenBaoNamespace())
			cur, err := bao.ReadCertAuthRole(ctx, r.Spec.Path, r.BaoName(), ns)
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{"role": cur}, nil
		},

		BaoWrite: func(ctx context.Context, r *v1alpha1.OpenBaoCertAuthEngineRole) (resource.StatusMutator[*v1alpha1.OpenBaoCertAuthEngineRole], error) {
			if err := checkRoleCollision(ctx, cl, r); err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(r.OpenBaoNamespace())
			if err := bao.WriteCertAuthRole(ctx, r.Spec.Path, r.BaoName(), r.ToBaoSpec(), ns); err != nil {
				return nil, err
			}
			pathSnapshot := r.Spec.Path
			return func(cur *v1alpha1.OpenBaoCertAuthEngineRole) {
				cur.Status.LastWrittenPath = pathSnapshot
			}, nil
		},

		BaoDelete: func(ctx context.Context, r *v1alpha1.OpenBaoCertAuthEngineRole) error {
			return bao.DeleteCertAuthRole(ctx, r.Spec.Path, r.BaoName(),
				baoclient.WithNamespace(r.OpenBaoNamespace()))
		},

		BaoDeleteIdentity: func(ctx context.Context, r *v1alpha1.OpenBaoCertAuthEngineRole, name, namespace string) error {
			// Use the bao mount path that was active when the
			// previous (name, namespace) was last written. A
			// simultaneous spec.name + spec.path edit otherwise
			// targets the new mount and silently 404s, orphaning
			// the role at the old (path, name).
			path := r.Status.LastWrittenPath
			if path == "" {
				path = r.Spec.Path
			}
			return bao.DeleteCertAuthRole(ctx, path, name,
				baoclient.WithNamespace(namespace))
		},

		CheckCollision: func(ctx context.Context, r *v1alpha1.OpenBaoCertAuthEngineRole) error {
			return checkRoleCollision(ctx, cl, r)
		},
	}
}

// checkRoleCollision returns ErrNameCollision when another CR (different
// UID) targets the same (openbaoNamespace, mount path, role name) tuple.
func checkRoleCollision(ctx context.Context, cl client.Client, r *v1alpha1.OpenBaoCertAuthEngineRole) error {
	var all v1alpha1.OpenBaoCertAuthEngineRoleList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoCertAuthEngineRoles for collision check: %v",
			resource.ErrInternal, err)
	}
	targetMount := r.Spec.Path
	targetName := r.BaoName()
	targetNS := r.OpenBaoNamespace()
	mineKey := r.Namespace + "/" + r.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == r.UID {
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
		case other.CreationTimestamp.Before(&r.CreationTimestamp):
			otherWins = true
		case r.CreationTimestamp.Before(&other.CreationTimestamp):
			otherWins = false
		default:
			otherKey := other.Namespace + "/" + other.Name
			otherWins = otherKey < mineKey
		}
		if otherWins {
			return fmt.Errorf("%w: bao cert role %q (mount=%q, ns=%q) already owned by OpenBaoCertAuthEngineRole %s/%s",
				resource.ErrNameCollision, targetName, targetMount, targetNS,
				other.Namespace, other.Name)
		}
	}
	return nil
}

// SetupWithManager wires the controller and watches the Secrets that
// supply the trusted CA bundle. A Secret rotation re-enqueues every
// Role CR whose spec.certificateRef points at that Secret, so the
// next reconcile picks up the new bundle.
func (r *OpenBaoCertAuthEngineRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoCertAuthEngineRole{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.rolesReferencingSecret),
		).
		Complete(r)
}

func (r *OpenBaoCertAuthEngineRoleReconciler) rolesReferencingSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	sec, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}
	var roles v1alpha1.OpenBaoCertAuthEngineRoleList
	if err := r.cl.List(ctx, &roles); err != nil {
		return nil
	}
	var out []reconcile.Request
	for i := range roles.Items {
		role := &roles.Items[i]
		if role.Spec.CertificateRef == nil {
			continue
		}
		refNS := role.Spec.CertificateRef.Namespace
		if refNS == "" {
			refNS = role.Namespace
		}
		if refNS == sec.Namespace && role.Spec.CertificateRef.Name == sec.Name {
			out = append(out, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: role.Namespace, Name: role.Name},
			})
		}
	}
	return out
}
