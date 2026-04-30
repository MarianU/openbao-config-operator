package openbaokubernetesauthrole

import (
	"context"
	"errors"
	"fmt"
	"os"

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

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaokubernetesauthroles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaokubernetesauthroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaokubernetesauthroles/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

// OpenBaoKubernetesAuthRoleFinalizer follows the Kubernetes convention
// <resource>.<group>/finalizer.
const OpenBaoKubernetesAuthRoleFinalizer = "openbaokubernetesauthrole.security.mto.stakater.com/finalizer"

type OpenBaoKubernetesAuthRoleReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoKubernetesAuthRole]
}

// NewOpenBaoKubernetesAuthRoleReconciler constructs the reconciler. The bao
// address and token come from VAULT_ADDR / VAULT_TOKEN (or BAO_ADDR /
// BAO_TOKEN) at startup; missing env is fatal so misconfiguration surfaces
// at process start, not during the first Reconcile.
func NewOpenBaoKubernetesAuthRoleReconciler(mgr ctrl.Manager) (*OpenBaoKubernetesAuthRoleReconciler, error) {
	bao, err := newBaoFromEnv()
	if err != nil {
		return nil, err
	}
	return NewOpenBaoKubernetesAuthRoleReconcilerWithClient(mgr, bao), nil
}

// NewOpenBaoKubernetesAuthRoleReconcilerWithClient is the test-friendly
// constructor.
func NewOpenBaoKubernetesAuthRoleReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoKubernetesAuthRoleReconciler {
	return &OpenBaoKubernetesAuthRoleReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoKubernetesAuthRole](mgr, OpenBaoKubernetesAuthRoleFinalizer,
			OpenBaoKubernetesAuthRoleHandlers(mgr.GetClient(), bao)),
	}
}

// OpenBaoKubernetesAuthRoleHandlers builds the bao-I/O callbacks. Exposed
// so tests can wire them into a hand-constructed VaultResource without a
// manager. Every bao call carries spec.openbaoNamespace as the
// X-Vault-Namespace header via baoclient.WithNamespace; empty (the
// default) targets root.
func OpenBaoKubernetesAuthRoleHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoKubernetesAuthRole] {
	return resource.Handlers[*v1alpha1.OpenBaoKubernetesAuthRole]{
		NewInstance: func() *v1alpha1.OpenBaoKubernetesAuthRole {
			return &v1alpha1.OpenBaoKubernetesAuthRole{}
		},
		BaoGet: func(ctx context.Context, r *v1alpha1.OpenBaoKubernetesAuthRole) (map[string]any, error) {
			role, err := bao.GetK8sRole(ctx, r.Spec.Path, r.BaoName(), baoclient.WithNamespace(r.OpenBaoNamespace()))
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return roleReadToPayload(role), nil
		},
		BaoWrite: func(ctx context.Context, r *v1alpha1.OpenBaoKubernetesAuthRole) (resource.StatusMutator[*v1alpha1.OpenBaoKubernetesAuthRole], error) {
			if err := checkRoleNameCollision(ctx, cl, r); err != nil {
				return nil, err
			}
			return nil, bao.UpsertK8sRole(ctx, r.Spec.Path, r.BaoName(), toK8sRoleSpec(r), baoclient.WithNamespace(r.OpenBaoNamespace()))
		},
		BaoDelete: func(ctx context.Context, r *v1alpha1.OpenBaoKubernetesAuthRole) error {
			return bao.DeleteK8sRole(ctx, r.Spec.Path, r.BaoName(), baoclient.WithNamespace(r.OpenBaoNamespace()))
		},
		CheckCollision: func(ctx context.Context, r *v1alpha1.OpenBaoKubernetesAuthRole) error {
			return checkRoleNameCollision(ctx, cl, r)
		},
		BaoDeleteIdentity: func(ctx context.Context, r *v1alpha1.OpenBaoKubernetesAuthRole, name, namespace string) error {
			// Rename cleanup uses the CR's current Spec.Path (auth mount
			// path) — same caveat as OpenBaoMount: status surface
			// records (role name, openbao namespace) but not the auth
			// mount path. A simultaneous spec.name + spec.path edit
			// would leave an orphan at the old (path, name) tuple.
			return bao.DeleteK8sRole(ctx, r.Spec.Path, name, baoclient.WithNamespace(namespace))
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
func toK8sRoleSpec(r *v1alpha1.OpenBaoKubernetesAuthRole) baoclient.K8sRoleSpec {
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
// OpenBaoKubernetesAuthRole CR (different UID) targets the same bao
// resource — same OpenBao namespace AND same auth path AND same role
// name. Two CRs with the same name on different mounts (e.g. two
// different Kubernetes clusters' auth) do NOT collide. Two CRs with
// the same path+name in different OpenBao namespaces also do NOT
// collide — bao isolates them via X-Vault-Namespace.
//
// Tie-break: older CreationTimestamp wins; on tie, lex order of
// <namespace>/<name> wins.
//
// Without this guard, two CRs in different k8s namespaces sharing
// (spec.openbaoNamespace, spec.path, metadata.name) silently overwrite
// each other's bao body on every reconcile, and a delete of one removes
// the bao role the other thinks it owns.
func checkRoleNameCollision(ctx context.Context, cl client.Client, r *v1alpha1.OpenBaoKubernetesAuthRole) error {
	var all v1alpha1.OpenBaoKubernetesAuthRoleList
	if err := cl.List(ctx, &all); err != nil {
		// Fail closed — better to surface a transient error than to
		// silently overwrite. ErrInternal classifies as InternalError
		// so an on-call paging on this condition checks the k8s
		// apiserver, not bao.
		return fmt.Errorf("%w: listing OpenBaoKubernetesAuthRoles for collision check: %v",
			resource.ErrInternal, err)
	}
	targetPath := r.GetPath()
	targetNS := r.OpenBaoNamespace()
	mineKey := r.Namespace + "/" + r.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == r.UID {
			continue
		}
		if other.GetPath() != targetPath {
			continue
		}
		if other.OpenBaoNamespace() != targetNS {
			// Same path in a different OpenBao namespace is not a
			// collision — bao isolates them via X-Vault-Namespace.
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
			return fmt.Errorf("%w: bao role %q in namespace %q already owned by OpenBaoKubernetesAuthRole %s/%s",
				resource.ErrNameCollision, targetPath, targetNS, other.Namespace, other.Name)
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
func (r *OpenBaoKubernetesAuthRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoKubernetesAuthRole{},
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
func (r *OpenBaoKubernetesAuthRoleReconciler) mapNamespaceToCRs(ctx context.Context, obj client.Object) []ctrlreconcile.Request {
	l := log.FromContext(ctx)
	ns, ok := obj.(*corev1.Namespace)
	if !ok {
		return nil
	}
	var all v1alpha1.OpenBaoKubernetesAuthRoleList
	if err := r.List(ctx, &all); err != nil {
		l.Error(err, "mapNamespaceToCRs: failed to list OpenBaoKubernetesAuthRoles; dropping the event",
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
		return nil, fmt.Errorf("set VAULT_ADDR/VAULT_TOKEN (or BAO_ADDR/BAO_TOKEN) for OpenBaoKubernetesAuthRoleReconciler")
	}
	return baoclient.NewHTTPClient(addr, token)
}
