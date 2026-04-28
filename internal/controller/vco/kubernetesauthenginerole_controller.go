package vco

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	vcov1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/vco/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=kubernetesauthengineroles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=kubernetesauthengineroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=kubernetesauthengineroles/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

// KubernetesAuthEngineRoleFinalizer follows the Kubernetes convention
// <resource>.<group>/finalizer.
const KubernetesAuthEngineRoleFinalizer = "kubernetesauthenginerole.security.mto.stakater.com/finalizer"

type KubernetesAuthEngineRoleReconciler struct {
	*resource.VaultResource[*vcov1alpha1.KubernetesAuthEngineRole]
}

// NewKubernetesAuthEngineRoleReconciler constructs the reconciler. The bao
// address and token come from VAULT_ADDR / VAULT_TOKEN (or BAO_ADDR /
// BAO_TOKEN) at startup — same env contract as PolicyReconciler.
func NewKubernetesAuthEngineRoleReconciler(mgr ctrl.Manager) (*KubernetesAuthEngineRoleReconciler, error) {
	bao, err := newBaoFromEnv()
	if err != nil {
		return nil, err
	}
	return NewKubernetesAuthEngineRoleReconcilerWithClient(mgr, bao), nil
}

// NewKubernetesAuthEngineRoleReconcilerWithClient is the test-friendly
// constructor.
func NewKubernetesAuthEngineRoleReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *KubernetesAuthEngineRoleReconciler {
	return &KubernetesAuthEngineRoleReconciler{
		VaultResource: resource.New[*vcov1alpha1.KubernetesAuthEngineRole](mgr, KubernetesAuthEngineRoleFinalizer,
			KubernetesAuthEngineRoleHandlers(mgr.GetClient(), bao)),
	}
}

// KubernetesAuthEngineRoleHandlers builds the bao-I/O callbacks. Exposed so
// tests can wire them into a hand-constructed VaultResource without a
// manager.
func KubernetesAuthEngineRoleHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*vcov1alpha1.KubernetesAuthEngineRole] {
	return resource.Handlers[*vcov1alpha1.KubernetesAuthEngineRole]{
		NewInstance: func() *vcov1alpha1.KubernetesAuthEngineRole {
			return &vcov1alpha1.KubernetesAuthEngineRole{}
		},
		BaoGet: func(ctx context.Context, r *vcov1alpha1.KubernetesAuthEngineRole) (map[string]any, error) {
			role, err := bao.GetK8sRole(ctx, r.Spec.Path, r.BaoName())
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return roleReadToPayload(role), nil
		},
		BaoWrite: func(ctx context.Context, r *vcov1alpha1.KubernetesAuthEngineRole) error {
			if err := checkRoleNameCollision(ctx, cl, r); err != nil {
				return err
			}
			return bao.UpsertK8sRole(ctx, r.Spec.Path, r.BaoName(), toK8sRoleSpec(r))
		},
		BaoDelete: func(ctx context.Context, r *vcov1alpha1.KubernetesAuthEngineRole) error {
			return bao.DeleteK8sRole(ctx, r.Spec.Path, r.BaoName())
		},
	}
}

// roleReadToPayload shapes a baoclient.K8sRole (read response) into the
// same map[string]any the type's GetPayload() emits, so the type's
// IsEquivalentToDesiredState can compare the two without bao-specific
// knowledge bleeding into the shared base.
//
// The token_num_uses and token_no_default_policy emit predicates treat
// the bao defaults (0 and false) as "unset" — bao echoes these fields
// in every read response even when they were never set by the upsert,
// so emitting them unconditionally would cause a permanent mismatch
// against the desired payload (which omits unset pointer fields) and
// trigger a re-upsert every 5 minutes. The omit-on-default rule keeps
// both sides agreeing. See VRole.toMap for the symmetric write-side.
func roleReadToPayload(role *baoclient.K8sRole) map[string]any {
	out := map[string]any{
		"bound_service_account_names":      role.BoundServiceAccountNames,
		"bound_service_account_namespaces": role.BoundServiceAccountNamespaces,
		"token_policies":                   role.Policies,
	}
	if role.AliasNameSource != "" {
		out["alias_name_source"] = role.AliasNameSource
	}
	if role.Audience != "" {
		out["audience"] = role.Audience
	}
	if role.TokenTTL != "" {
		out["token_ttl"] = role.TokenTTL
	}
	if role.TokenMaxTTL != "" {
		out["token_max_ttl"] = role.TokenMaxTTL
	}
	if len(role.TokenBoundCIDRs) > 0 {
		out["token_bound_cidrs"] = role.TokenBoundCIDRs
	}
	if role.TokenExplicitMaxTTL != "" {
		out["token_explicit_max_ttl"] = role.TokenExplicitMaxTTL
	}
	if role.TokenNoDefaultPolicy != nil && *role.TokenNoDefaultPolicy {
		out["token_no_default_policy"] = true
	}
	if role.TokenNumUses != nil && *role.TokenNumUses != 0 {
		out["token_num_uses"] = *role.TokenNumUses
	}
	if role.TokenPeriod != "" {
		out["token_period"] = role.TokenPeriod
	}
	if role.TokenType != "" {
		out["token_type"] = role.TokenType
	}
	return out
}

// toK8sRoleSpec converts the CRD's resolved state into the wrapper
// client's write payload. The bound-namespace list comes from the
// resolved internal field that PrepareInternalValues populated.
func toK8sRoleSpec(r *vcov1alpha1.KubernetesAuthEngineRole) baoclient.K8sRoleSpec {
	return baoclient.K8sRoleSpec{
		Policies:                      r.Spec.Policies,
		BoundServiceAccountNames:      r.Spec.TargetServiceAccounts,
		BoundServiceAccountNamespaces: r.BoundNamespaces(),
		Audience:                      r.Spec.Audience,
		AliasNameSource:               r.Spec.AliasNameSource,
		TokenBoundCIDRs:               r.Spec.TokenBoundCIDRs,
		TokenTTL:                      r.Spec.TokenTTL,
		TokenMaxTTL:                   r.Spec.TokenMaxTTL,
		TokenExplicitMaxTTL:           r.Spec.TokenExplicitMaxTTL,
		TokenNoDefaultPolicy:          r.Spec.TokenNoDefaultPolicy,
		TokenNumUses:                  r.Spec.TokenNumUses,
		TokenPeriod:                   r.Spec.TokenPeriod,
		TokenType:                     r.Spec.TokenType,
	}
}

// checkRoleNameCollision returns ErrNameCollision when another
// KubernetesAuthEngineRole CR (different UID) targets the same bao path
// — same spec.path AND same BaoName(). Two CRs with the same name on
// different mounts (e.g. two different Kubernetes clusters' auth) do
// NOT collide. Tie-break: older CreationTimestamp wins; on tie, lex
// order of <namespace>/<name> wins.
//
// Without this guard, two CRs in different k8s namespaces sharing
// (spec.path, metadata.name) silently overwrite each other's bao body
// on every reconcile, and a delete of one removes the bao role the
// other thinks it owns.
func checkRoleNameCollision(ctx context.Context, cl client.Client, r *vcov1alpha1.KubernetesAuthEngineRole) error {
	var all vcov1alpha1.KubernetesAuthEngineRoleList
	if err := cl.List(ctx, &all); err != nil {
		// Fail closed — better to surface a transient error than to
		// silently overwrite. ErrInternal classifies as InternalError
		// so an on-call paging on this condition checks the k8s
		// apiserver, not bao.
		return fmt.Errorf("%w: listing KubernetesAuthEngineRoles for collision check: %v",
			resource.ErrInternal, err)
	}
	targetPath := r.GetPath()
	mineKey := r.Namespace + "/" + r.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == r.UID {
			continue
		}
		if other.GetPath() != targetPath {
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
			return fmt.Errorf("%w: bao role %q already owned by KubernetesAuthEngineRole %s/%s",
				resource.ErrNameCollision, targetPath, other.Namespace, other.Name)
		}
	}
	return nil
}

// SetupWithManager registers the controller with a GenerationChangedPredicate
// (so status writes do not trigger re-reconciles) plus a Namespace watch
// that maps label-change events to any CR whose targetNamespaceSelector
// matches the changed namespace's labels.
//
// LabelChangedPredicate filters Update events to only those with a label
// diff. Create and Delete events fall through to default accept-all in
// TypedFuncs, so namespace creation and deletion also reach mapFn —
// exactly the events that change which CRs match.
func (r *KubernetesAuthEngineRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vcov1alpha1.KubernetesAuthEngineRole{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(
			&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(r.mapNamespaceToCRs),
			builder.WithPredicates(predicate.LabelChangedPredicate{}),
		).
		Complete(r)
}

// mapNamespaceToCRs returns reconcile requests for every CR whose
// targetNamespaceSelector matches the changed namespace's labels.
// CRs that use the literal targetNamespaces list are skipped because
// namespace label changes are irrelevant to them.
//
// On a List failure we log and return nil rather than propagating the
// error: controller-runtime expects the map function to be best-effort,
// and a transient apiserver hiccup should not break the watch wiring.
// The next user-driven reconcile (or the next label change) will retry.
func (r *KubernetesAuthEngineRoleReconciler) mapNamespaceToCRs(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
	l := log.FromContext(ctx)
	ns, ok := obj.(*corev1.Namespace)
	if !ok {
		return nil
	}
	var all vcov1alpha1.KubernetesAuthEngineRoleList
	if err := r.List(ctx, &all); err != nil {
		l.Error(err, "mapNamespaceToCRs: failed to list KubernetesAuthEngineRoles; dropping the event",
			"namespace", ns.Name)
		return nil
	}
	out := make([]ctrlreconcile.Request, 0, len(all.Items))
	nsLabels := labels.Set(ns.Labels)
	for i := range all.Items {
		cr := &all.Items[i]
		sel := cr.Spec.TargetNamespaces.TargetNamespaceSelector
		if sel == nil {
			continue
		}
		s, err := metav1.LabelSelectorAsSelector(sel)
		if err != nil {
			l.Error(err, "mapNamespaceToCRs: invalid label selector on CR; skipping",
				"cr", cr.Namespace+"/"+cr.Name)
			continue
		}
		if !s.Matches(nsLabels) {
			continue
		}
		out = append(out, ctrlreconcile.Request{NamespacedName: types.NamespacedName{Namespace: cr.Namespace, Name: cr.Name}})
	}
	return out
}
