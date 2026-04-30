// +kubebuilder:rbac:groups=tenantoperator.stakater.com,resources=tenants,verbs=get;list;watch
// +kubebuilder:rbac:groups=tenantoperator.stakater.com,resources=tenants/status,verbs=get
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoextensions,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoextensions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaopolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaokubernetesauthroles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaosecretengines,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaonamespaces,verbs=get;list;watch;create;update;patch;delete

package tenant

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	extv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	"github.com/stakater-ab/mto-extension-openbao/internal/constants"
	utils "github.com/stakater-ab/mto-extension-openbao/internal/utils"
	mto "github.com/stakater-ab/tenant-operator/api/v1beta3"
)

// childNamespaceFallback is where emitted sub-CRs land when the
// OpenBaoExtension's metadata.namespace is somehow empty (shouldn't
// happen — OBX is namespaced — but defense in depth keeps the
// reconciler from creating cluster-wide chaos by writing to the
// "default" namespace by accident).
const childNamespaceFallback = "mto-extension-openbao-system"

// reconcileBackoff is how long the reconciler waits before retrying
// after a transient k8s-side failure.
const reconcileBackoff = 30 * time.Second

type TenantReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger

	env string // e.g., "prod"
}

func NewTenantReconciler(mgr ctrl.Manager) (*TenantReconciler, error) {
	return &TenantReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Log:    ctrl.Log.WithName("controller").WithName("Tenant"),
		env:    constants.DefaultEnv,
	}, nil
}

func (r *TenantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("tenant", req.Name)

	var t mto.Tenant
	if err := r.Get(ctx, req.NamespacedName, &t); err != nil {
		if apierrors.IsNotFound(err) {
			// Tenant deletion: owner refs cascade-delete the emitted
			// sub-CRs automatically, so no manual cleanup needed here.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	var extList extv1alpha1.OpenBaoExtensionList
	if err := r.List(ctx, &extList); err != nil && !apierrors.IsNotFound(err) {
		// A transient List failure makes the controller silently take the
		// hard-gate branch below. Log so the failure is debuggable; we
		// still fall through to the gate so a partial list doesn't
		// surface as success.
		log.Error(err, "list OpenBaoExtension failed; tenant reconcile will hard-gate")
	}
	ext := r.firstOpenBaoExtension(&extList)

	// Hard gate: do not emit children or write status until the cluster's
	// OpenBaoExtension reports AuthConfigured=True. This eliminates a
	// race with the ClusterAuth controller where a Tenant could emit
	// k8s-auth roles against a not-yet-enabled bao auth mount.
	if ext == nil || !hasCondTrue(ext, extv1alpha1.CondAuthConfigured) {
		return ctrl.Result{RequeueAfter: reconcileBackoff}, nil
	}

	// Status mutation is published exactly once at the end of Reconcile.
	finalStatus := metav1.ConditionTrue
	finalReason := extv1alpha1.ReasonSuccess
	finalMessage := "All tenants reconciled."
	defer func() {
		if ext == nil {
			return
		}
		utils.RemoveCondGen(ext, extv1alpha1.CondTenantsReconciled)
		utils.SetCondGen(ext, extv1alpha1.CondTenantsReconciled, finalStatus, finalReason, finalMessage)
		if err := r.patchStatus(ctx, ext); err != nil && !apierrors.IsNotFound(err) {
			log.Error(err, "failed to write TenantsReconciled status",
				"openbaoextension", ext.Namespace+"/"+ext.Name, "reason", finalReason)
		}
	}()

	// Where do emitted sub-CRs live? Operator's own namespace — same as
	// the OpenBaoExtension. Cluster-scoped Tenant → namespaced child is
	// a legal owner-ref relationship per kubernetes/owners-dependents.
	childNS := ext.Namespace
	if childNS == "" {
		childNS = childNamespaceFallback
	}

	mode := resolveMode(ext)
	desired := r.planChildren(&t, ext, mode, childNS)

	if err := r.upsertChildren(ctx, &t, desired); err != nil {
		log.Error(err, "failed to upsert child sub-CRs")
		finalStatus = metav1.ConditionFalse
		finalReason = extv1alpha1.ReasonError
		finalMessage = err.Error()
		return ctrl.Result{RequeueAfter: reconcileBackoff}, nil
	}

	if err := r.pruneOrphans(ctx, &t, desired, childNS); err != nil {
		// Pruning failure is not fatal — the orphan stays around until
		// the next reconcile. Log and continue so the user-facing status
		// reflects the upsert outcome rather than the GC outcome.
		log.Error(err, "orphan pruning encountered errors; will retry on next reconcile")
	}

	notReady, agg := r.aggregateChildStatus(ctx, desired)
	if len(notReady) > 0 {
		finalStatus = metav1.ConditionFalse
		finalReason = extv1alpha1.ReasonError
		finalMessage = fmt.Sprintf("child sub-CR(s) not Ready: %s", strings.Join(notReady, ", "))
		// Children may still be converging (drift correction, etc.).
		// Requeue at the standard error backoff so this Tenant catches
		// the next status flip even if the Owns watch missed an event.
		return ctrl.Result{RequeueAfter: reconcileBackoff}, nil
	}
	finalMessage = agg
	return ctrl.Result{}, nil
}

// resolveMode returns the cluster-wide tenancy mode from the
// OpenBaoExtension. Defaults to TenancyNamespace per ADR-0001 if the
// CR omits the field (which can happen before defaults propagate
// through admission, or with hand-rolled CRs).
func resolveMode(ext *extv1alpha1.OpenBaoExtension) extv1alpha1.TenancyMode {
	if ext == nil || ext.Spec.Tenancy.Mode == "" {
		return extv1alpha1.TenancyNamespace
	}
	return ext.Spec.Tenancy.Mode
}

// childKey identifies a desired sub-CR by its k8s metadata. The
// reconciler uses the kind+name to decide upsert vs prune.
type childKey struct {
	gvk  string
	name string
}

// desiredChild bundles a sub-CR with its k8s identity. Stored as
// client.Object for kind-uniform handling at upsert + status time.
type desiredChild struct {
	key  childKey
	cr   client.Object
	kind string // human-readable for status messages
}

// planChildren computes the desired set of sub-CRs for a Tenant.
// Mode A emits an OpenBaoNamespace + per-tenant OpenBaoSecretEngine(KV)
// + per-k8s-namespace OpenBaoPolicy + OpenBaoKubernetesAuthRole, all
// targeting spec.openbaoNamespace=<tenant>/. Mode B emits only the
// per-namespace Policy + Role with empty spec.openbaoNamespace and
// tenant-prefixed bao-side names.
//
// The kubernetes auth mount itself is enabled by clusterauth at startup
// (auth/kubernetes lives at root, shared across tenants); per-tenant
// scoping is achieved by minting tenant-scoped roles inside that mount.
//
// The bao-side end-state in Mode B matches the previous imperative
// implementation byte-for-byte.
func (r *TenantReconciler) planChildren(t *mto.Tenant, ext *extv1alpha1.OpenBaoExtension, mode extv1alpha1.TenancyMode, childNS string) []desiredChild {
	tenant := t.GetName()

	type nsEntry struct {
		short      string
		withPrefix bool
	}
	var wanted []nsEntry
	if t.Spec.Namespaces != nil {
		for _, s := range t.Spec.Namespaces.WithTenantPrefix {
			wanted = append(wanted, nsEntry{short: string(s), withPrefix: true})
		}
		for _, s := range t.Spec.Namespaces.WithoutTenantPrefix {
			wanted = append(wanted, nsEntry{short: string(s), withPrefix: false})
		}
	}

	editorCaps := effectiveCaps(&ext.Spec, "editor")
	tokenTTL := leaseString(ext.Spec.RBAC.Token.TTL)
	tokenMaxTTL := leaseString(ext.Spec.RBAC.Token.MaxTTL)

	out := make([]desiredChild, 0, len(wanted)*2+3)

	// ---- Mode A: bao namespace + per-tenant mounts ----
	openBaoNS := ""
	if mode == extv1alpha1.TenancyNamespace {
		openBaoNS = tenant + "/"

		out = append(out, makeOpenBaoNamespace(tenant, childNS))
		out = append(out, makeOpenBaoSecretEngineKV(tenant, openBaoNS, childNS))
	}

	// ---- Per-namespace policies + roles (both modes) ----
	for _, it := range wanted {
		nsFull := utils.NamespaceFull(tenant, it.short, it.withPrefix)
		out = append(out, makeOpenBaoPolicy(tenant, nsFull, openBaoNS, mode, r.kvMount(), r.env, editorCaps, childNS))
		out = append(out, makeOpenBaoKubernetesAuthRole(tenant, nsFull, openBaoNS, mode, tokenTTL, tokenMaxTTL, ext.Spec.RBAC.Token.Renewable, childNS))
	}

	return out
}

// kvMount returns the bao-side KV mount path the operator targets.
// Today it's a constant; lifted onto the receiver so a future
// OpenBaoExtension.spec.engines override can plug in here without
// changing every caller.
func (r *TenantReconciler) kvMount() string { return constants.DefaultKVMount }

// makeOpenBaoNamespace constructs the per-Tenant OpenBaoNamespace CR
// for Mode A. The bao-side namespace name is `<tenant>` and lives at
// the bao root (no parent context).
func makeOpenBaoNamespace(tenant, childNS string) desiredChild {
	cr := &extv1alpha1.OpenBaoNamespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tenantChildName(tenant, "namespace"),
			Namespace: childNS,
		},
		Spec: extv1alpha1.OpenBaoNamespaceSpec{
			Name: tenant,
		},
	}
	return desiredChild{
		key:  childKey{gvk: gvkOpenBaoNamespace, name: cr.Name},
		cr:   cr,
		kind: "OpenBaoNamespace",
	}
}

// makeOpenBaoSecretEngineKV constructs the per-Tenant OpenBaoSecretEngine
// for the KV-v2 secret engine inside the tenant's bao namespace (Mode A).
func makeOpenBaoSecretEngineKV(tenant, openBaoNS, childNS string) desiredChild {
	cr := &extv1alpha1.OpenBaoSecretEngine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tenantChildName(tenant, "kv"),
			Namespace: childNS,
		},
		Spec: extv1alpha1.OpenBaoSecretEngineSpec{
			Path:             constants.DefaultKVMount,
			OpenBaoNamespace: openBaoNS,
			KvV2:             &extv1alpha1.KvV2Spec{},
		},
	}
	return desiredChild{
		key:  childKey{gvk: gvkOpenBaoSecretEngine, name: cr.Name},
		cr:   cr,
		kind: "OpenBaoSecretEngine(kv)",
	}
}

// makeOpenBaoPolicy constructs an OpenBaoPolicy for one k8s namespace.
// In Mode A the bao-side policy name is short (the bao namespace
// scopes it); in Mode B the name carries the tenant prefix to
// disambiguate at the global root mount.
func makeOpenBaoPolicy(tenant, nsFull, openBaoNS string, mode extv1alpha1.TenancyMode, kvMount, env string, caps []string, childNS string) desiredChild {
	var baoName string
	if mode == extv1alpha1.TenancyNamespace {
		baoName = nsFull + "-editor"
	} else {
		baoName = utils.PolicyNameEditor(tenant, nsFull)
	}
	cr := &extv1alpha1.OpenBaoPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tenantChildName(tenant, "policy-"+nsFull),
			Namespace: childNS,
		},
		Spec: extv1alpha1.OpenBaoPolicySpec{
			Name:             baoName,
			OpenBaoNamespace: openBaoNS,
			Policy:           buildKVv2NamespacePolicy(kvMount, tenant, env, nsFull, caps),
		},
	}
	return desiredChild{
		key:  childKey{gvk: gvkOpenBaoPolicy, name: cr.Name},
		cr:   cr,
		kind: "OpenBaoPolicy",
	}
}

// makeOpenBaoKubernetesAuthRole constructs the per-namespace role.
func makeOpenBaoKubernetesAuthRole(tenant, nsFull, openBaoNS string, mode extv1alpha1.TenancyMode, tokenTTL, tokenMaxTTL string, renewable *bool, childNS string) desiredChild {
	var policyName string
	var roleName string
	if mode == extv1alpha1.TenancyNamespace {
		policyName = nsFull + "-editor"
		roleName = nsFull
	} else {
		policyName = utils.PolicyNameEditor(tenant, nsFull)
		roleName = utils.RoleName(tenant, nsFull)
	}
	cr := &extv1alpha1.OpenBaoKubernetesAuthRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tenantChildName(tenant, "role-"+nsFull),
			Namespace: childNS,
		},
		Spec: extv1alpha1.OpenBaoKubernetesAuthRoleSpec{
			Name:             roleName,
			OpenBaoNamespace: openBaoNS,
			Path:             constants.DefaultAuthMount,
			TargetNamespaces: extv1alpha1.TargetNamespaceConfig{
				TargetNamespaces: []string{nsFull},
			},
			VRole: extv1alpha1.VRole{
				Policies:              []string{policyName},
				TargetServiceAccounts: []string{"default"},
				TokenTTL:              tokenTTL,
				TokenMaxTTL:           tokenMaxTTL,
			},
		},
	}
	if renewable != nil {
		// VRole has no explicit Renewable field upstream-equivalently;
		// preserved here as a no-op to match the imperative path's
		// shape — when bao role payload gains a Renewable hook the
		// field is plumbed through the existing VRole struct.
		_ = renewable
	}
	return desiredChild{
		key:  childKey{gvk: gvkOpenBaoKubernetesAuthRole, name: cr.Name},
		cr:   cr,
		kind: "OpenBaoKubernetesAuthRole",
	}
}

// tenantChildName builds a DNS-1123 metadata.name for a sub-CR, scoped
// to a tenant. The format is "<tenant>-<purpose>"; the purpose tag
// disambiguates kinds inside the operator's namespace (a Policy and
// Role for the same nsFull would otherwise collide on metadata.name).
func tenantChildName(tenant, purpose string) string {
	return strings.ToLower(tenant + "-" + purpose)
}

// upsertChildren creates or updates each desired sub-CR with an owner
// ref to the Tenant. The owner ref makes k8s garbage-collect children
// when the Tenant is deleted, so this controller's deletion path is a
// no-op (handled by the IsNotFound branch in Reconcile).
//
// Errors return early — partial-success isn't useful here because the
// status aggregation in Reconcile will surface every child's Ready
// state once they're all upserted.
func (r *TenantReconciler) upsertChildren(ctx context.Context, owner *mto.Tenant, desired []desiredChild) error {
	for i := range desired {
		d := desired[i]

		// Set the controller-owner ref BEFORE create. SetControllerReference
		// rejects setting a second controller; we treat the first one
		// as authoritative.
		if err := controllerutil.SetControllerReference(owner, d.cr, r.Scheme); err != nil {
			return fmt.Errorf("set owner ref on %s/%s: %w", d.kind, d.cr.GetName(), err)
		}

		// Use the spec from `desired` as the desired-state snapshot;
		// CreateOrUpdate fetches the live object and merges via the
		// mutate function.
		desiredSpec := d.cr.DeepCopyObject().(client.Object)
		_, err := controllerutil.CreateOrUpdate(ctx, r.Client, d.cr, func() error {
			// d.cr is the live object after Get; copy spec from desired
			// without trampling status, ownerRefs (already set via
			// SetControllerReference above), or finalizers (set by the
			// child controller).
			copySpec(desiredSpec, d.cr)
			return nil
		})
		if err != nil {
			return fmt.Errorf("upsert %s/%s: %w", d.kind, d.cr.GetName(), err)
		}
	}
	return nil
}

// copySpec replaces the .spec of dst with the .spec of src using a
// kind-specific switch. Reflection would be tidier but fragile across
// CRD shape changes; the explicit switch keeps the touch points
// visible to a future primitive author.
func copySpec(src, dst client.Object) {
	switch s := src.(type) {
	case *extv1alpha1.OpenBaoNamespace:
		dst.(*extv1alpha1.OpenBaoNamespace).Spec = s.Spec
	case *extv1alpha1.OpenBaoSecretEngine:
		dst.(*extv1alpha1.OpenBaoSecretEngine).Spec = s.Spec
	case *extv1alpha1.OpenBaoPolicy:
		dst.(*extv1alpha1.OpenBaoPolicy).Spec = s.Spec
	case *extv1alpha1.OpenBaoKubernetesAuthRole:
		dst.(*extv1alpha1.OpenBaoKubernetesAuthRole).Spec = s.Spec
	}
}

// pruneOrphans deletes sub-CRs that are owned by this Tenant but no
// longer in the desired set (e.g. user removed a k8s namespace from
// tenant.spec.namespaces). The controller listing is filtered by
// owner UID so cross-tenant interference is not possible.
func (r *TenantReconciler) pruneOrphans(ctx context.Context, owner *mto.Tenant, desired []desiredChild, childNS string) error {
	want := make(map[childKey]struct{}, len(desired))
	for _, d := range desired {
		want[d.key] = struct{}{}
	}

	for _, listFn := range []func(context.Context, *mto.Tenant, string, map[childKey]struct{}) error{
		r.pruneOrphanPolicies,
		r.pruneOrphanRoles,
		r.pruneOrphanSecretEngines,
		r.pruneOrphanNamespaces,
	} {
		if err := listFn(ctx, owner, childNS, want); err != nil {
			return err
		}
	}
	return nil
}

func (r *TenantReconciler) pruneOrphanPolicies(ctx context.Context, owner *mto.Tenant, childNS string, want map[childKey]struct{}) error {
	var list extv1alpha1.OpenBaoPolicyList
	if err := r.List(ctx, &list, client.InNamespace(childNS)); err != nil {
		return err
	}
	for i := range list.Items {
		c := &list.Items[i]
		if !ownedByTenant(c, owner) {
			continue
		}
		if _, keep := want[childKey{gvk: gvkOpenBaoPolicy, name: c.Name}]; keep {
			continue
		}
		if err := r.Delete(ctx, c); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete orphan OpenBaoPolicy %s: %w", c.Name, err)
		}
	}
	return nil
}

func (r *TenantReconciler) pruneOrphanRoles(ctx context.Context, owner *mto.Tenant, childNS string, want map[childKey]struct{}) error {
	var list extv1alpha1.OpenBaoKubernetesAuthRoleList
	if err := r.List(ctx, &list, client.InNamespace(childNS)); err != nil {
		return err
	}
	for i := range list.Items {
		c := &list.Items[i]
		if !ownedByTenant(c, owner) {
			continue
		}
		if _, keep := want[childKey{gvk: gvkOpenBaoKubernetesAuthRole, name: c.Name}]; keep {
			continue
		}
		if err := r.Delete(ctx, c); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete orphan OpenBaoKubernetesAuthRole %s: %w", c.Name, err)
		}
	}
	return nil
}

func (r *TenantReconciler) pruneOrphanSecretEngines(ctx context.Context, owner *mto.Tenant, childNS string, want map[childKey]struct{}) error {
	var list extv1alpha1.OpenBaoSecretEngineList
	if err := r.List(ctx, &list, client.InNamespace(childNS)); err != nil {
		return err
	}
	for i := range list.Items {
		c := &list.Items[i]
		if !ownedByTenant(c, owner) {
			continue
		}
		if _, keep := want[childKey{gvk: gvkOpenBaoSecretEngine, name: c.Name}]; keep {
			continue
		}
		if err := r.Delete(ctx, c); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete orphan OpenBaoSecretEngine %s: %w", c.Name, err)
		}
	}
	return nil
}

func (r *TenantReconciler) pruneOrphanNamespaces(ctx context.Context, owner *mto.Tenant, childNS string, want map[childKey]struct{}) error {
	var list extv1alpha1.OpenBaoNamespaceList
	if err := r.List(ctx, &list, client.InNamespace(childNS)); err != nil {
		return err
	}
	for i := range list.Items {
		c := &list.Items[i]
		if !ownedByTenant(c, owner) {
			continue
		}
		if _, keep := want[childKey{gvk: gvkOpenBaoNamespace, name: c.Name}]; keep {
			continue
		}
		if err := r.Delete(ctx, c); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete orphan OpenBaoNamespace %s: %w", c.Name, err)
		}
	}
	return nil
}

// ownedByTenant returns true when obj has a controller-owner ref
// pointing at owner.UID. Pre-filtering by UID prevents a list call
// from one Tenant's reconcile from clobbering a different Tenant's
// children if their k8s metadata.name happened to overlap.
func ownedByTenant(obj client.Object, owner *mto.Tenant) bool {
	for _, ref := range obj.GetOwnerReferences() {
		if ref.Controller != nil && *ref.Controller && ref.UID == owner.UID {
			return true
		}
	}
	return false
}

// aggregateChildStatus inspects the live children and reports which
// (if any) are not Ready. The returned message describes the rollup;
// the not-ready slice carries `<kind>/<name>` identifiers for status.
func (r *TenantReconciler) aggregateChildStatus(ctx context.Context, desired []desiredChild) (notReady []string, summary string) {
	for i := range desired {
		d := desired[i]
		// Re-Get the live object to read its status; the in-memory
		// `d.cr` reflects the desired-state copy plus whatever
		// CreateOrUpdate populated, not necessarily the latest status.
		live := newEmptyChild(d.cr)
		key := types.NamespacedName{Namespace: d.cr.GetNamespace(), Name: d.cr.GetName()}
		if err := r.Get(ctx, key, live); err != nil {
			if apierrors.IsNotFound(err) {
				notReady = append(notReady, d.kind+"/"+d.cr.GetName()+" (not found)")
				continue
			}
			notReady = append(notReady, d.kind+"/"+d.cr.GetName()+" (status read failed)")
			continue
		}
		conds := getConditions(live)
		ready := apimeta.FindStatusCondition(conds, "Ready")
		if ready == nil || ready.Status != metav1.ConditionTrue {
			reason := "no Ready condition"
			if ready != nil {
				reason = ready.Reason
			}
			notReady = append(notReady, d.kind+"/"+d.cr.GetName()+" ("+reason+")")
		}
	}
	if len(notReady) == 0 {
		summary = fmt.Sprintf("All %d sub-CRs Ready.", len(desired))
	} else {
		summary = fmt.Sprintf("%d of %d sub-CRs Ready.", len(desired)-len(notReady), len(desired))
	}
	return notReady, summary
}

// newEmptyChild constructs a fresh, kind-matched empty CR for the
// supplied desired child. Used by aggregateChildStatus to read live
// state without polluting the desired-spec copy.
func newEmptyChild(of client.Object) client.Object {
	switch of.(type) {
	case *extv1alpha1.OpenBaoNamespace:
		return &extv1alpha1.OpenBaoNamespace{}
	case *extv1alpha1.OpenBaoSecretEngine:
		return &extv1alpha1.OpenBaoSecretEngine{}
	case *extv1alpha1.OpenBaoPolicy:
		return &extv1alpha1.OpenBaoPolicy{}
	case *extv1alpha1.OpenBaoKubernetesAuthRole:
		return &extv1alpha1.OpenBaoKubernetesAuthRole{}
	}
	return nil
}

// getConditions extracts the .status.conditions slice from a sub-CR
// regardless of kind.
func getConditions(obj client.Object) []metav1.Condition {
	switch o := obj.(type) {
	case *extv1alpha1.OpenBaoNamespace:
		return o.Status.Conditions
	case *extv1alpha1.OpenBaoSecretEngine:
		return o.Status.Conditions
	case *extv1alpha1.OpenBaoPolicy:
		return o.Status.Conditions
	case *extv1alpha1.OpenBaoKubernetesAuthRole:
		return o.Status.Conditions
	}
	return nil
}

// SetupWithManager registers Owns watches on every sub-CRD this
// controller emits. A child status flip re-reconciles the owning
// Tenant so aggregated status can refresh; cascading delete via
// owner refs already removes children when the Tenant is deleted.
func (r *TenantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mto.Tenant{}).
		Owns(&extv1alpha1.OpenBaoNamespace{}).
		Owns(&extv1alpha1.OpenBaoSecretEngine{}).
		Owns(&extv1alpha1.OpenBaoPolicy{}).
		Owns(&extv1alpha1.OpenBaoKubernetesAuthRole{}).
		Watches(
			&extv1alpha1.OpenBaoExtension{},
			handler.EnqueueRequestsFromMapFunc(r.mapExtensionToAllTenants),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Complete(r)
}

// mapExtensionToAllTenants enqueues every Tenant when the
// OpenBaoExtension's spec changes. Tenancy mode is the canonical
// driver — a flip from path → namespace must replan every Tenant's
// emitted sub-CRs in one batch rather than waiting for each Tenant's
// next event.
func (r *TenantReconciler) mapExtensionToAllTenants(ctx context.Context, _ client.Object) []ctrlreconcile.Request {
	var tenants mto.TenantList
	if err := r.List(ctx, &tenants); err != nil {
		return nil
	}
	out := make([]ctrlreconcile.Request, 0, len(tenants.Items))
	for i := range tenants.Items {
		out = append(out, ctrlreconcile.Request{
			NamespacedName: types.NamespacedName{Name: tenants.Items[i].Name},
		})
	}
	return out
}

// GVK identifiers used by childKey. Stored as strings so map keys
// stay comparable; the human-readable kind name lives on
// desiredChild.kind.
const (
	gvkOpenBaoNamespace          = "OpenBaoNamespace"
	gvkOpenBaoSecretEngine       = "OpenBaoSecretEngine"
	gvkOpenBaoPolicy             = "OpenBaoPolicy"
	gvkOpenBaoKubernetesAuthRole = "OpenBaoKubernetesAuthRole"
)

// ---- Pure helpers (unchanged from imperative impl) ----

// leaseString formats a metav1.Duration as "<secs>s" — the bao
// duration format compatible with both Vault and OpenBao.
func leaseString(d *metav1.Duration) string {
	if d == nil {
		return ""
	}
	s := int64(d.Duration / time.Second)
	if s < 0 {
		s = 0
	}
	return fmt.Sprintf("%ds", s)
}

// builtinCaps are the operator's defaults when no PolicyOverrides are
// provided. Each tier replaces the default via spec.policyOverrides.
var builtinCaps = map[string][]string{
	"admin":  {"create", "read", "update", "delete", "list"},
	"editor": {"create", "read", "update", "list"},
	"viewer": {"read", "list"},
}

// effectiveCaps computes the effective capability set for a tier from
// the OpenBaoExtension spec. Override replaces (does not merge) the
// default. Safety.AllowDeletes=false strips "delete" regardless of
// override.
func effectiveCaps(spec *extv1alpha1.OpenBaoExtensionSpec, tier string) []string {
	base := builtinCaps[tier]
	caps := append([]string(nil), base...)

	if spec != nil && spec.PolicyOverrides != nil {
		switch tier {
		case "admin":
			if spec.PolicyOverrides.Admin != nil && len(spec.PolicyOverrides.Admin.Capabilities) > 0 {
				caps = append([]string(nil), toStrings(spec.PolicyOverrides.Admin.Capabilities)...)
			}
		case "editor":
			if spec.PolicyOverrides.Editor != nil && len(spec.PolicyOverrides.Editor.Capabilities) > 0 {
				caps = append([]string(nil), toStrings(spec.PolicyOverrides.Editor.Capabilities)...)
			}
		case "viewer":
			if spec.PolicyOverrides.Viewer != nil && len(spec.PolicyOverrides.Viewer.Capabilities) > 0 {
				caps = append([]string(nil), toStrings(spec.PolicyOverrides.Viewer.Capabilities)...)
			}
		}
	}

	allowDeletes := false
	if spec != nil {
		allowDeletes = spec.Safety.AllowDeletes
	}
	if !allowDeletes {
		caps = filterOut(caps, "delete")
	}
	return dedupeKeepOrder(caps)
}

// buildKVv2NamespacePolicy emits the HCL body for an editor policy
// scoped to a tenant's k8s namespace under the operator's KV-v2 path
// layout (tenants/<tenant>/<env>/<nsFull>).
func buildKVv2NamespacePolicy(kvMount, tenant, env, nsFull string, caps []string) string {
	prefix := fmt.Sprintf("tenants/%s/%s/%s", strings.ToLower(tenant), env, nsFull)
	has := func(verb string) bool { return contains(caps, verb) }

	var b strings.Builder

	var dataCaps []string
	if has("create") {
		dataCaps = append(dataCaps, "create")
	}
	if has("update") {
		dataCaps = append(dataCaps, "update")
	}
	if has("read") {
		dataCaps = append(dataCaps, "read")
	}
	if has("delete") {
		dataCaps = append(dataCaps, "delete")
	}
	if len(dataCaps) > 0 {
		fmt.Fprintf(&b, "path \"%s/data/%s/*\" {\n  capabilities = [%s]\n}\n\n",
			kvMount, prefix, quotedCSV(dataCaps))
	}

	var metaCaps []string
	if has("read") {
		metaCaps = append(metaCaps, "read")
	}
	if has("list") {
		metaCaps = append(metaCaps, "list")
	}
	if len(metaCaps) > 0 {
		fmt.Fprintf(&b, "path \"%s/metadata/%s/*\" {\n  capabilities = [%s]\n}\n\n",
			kvMount, prefix, quotedCSV(metaCaps))
		if has("list") {
			fmt.Fprintf(&b, "path \"%s/metadata/%s\" {\n  capabilities = [\"list\"]\n}\n\n",
				kvMount, prefix)
		}
	}

	return b.String()
}

func filterOut(in []string, forbid string) []string {
	// Allocate a fresh slice — never reuse in's backing array.
	// Today no caller relies on the input post-call, but a future
	// caller that holds the slice past this call would observe
	// silent mutation if we did `in[:0]` here.
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v != forbid {
			out = append(out, v)
		}
	}
	return out
}

func dedupeKeepOrder(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func contains(in []string, needle string) bool {
	for _, v := range in {
		if v == needle {
			return true
		}
	}
	return false
}

func quotedCSV(in []string) string {
	if len(in) == 0 {
		return ""
	}
	tmp := make([]string, len(in))
	for i := range in {
		tmp[i] = fmt.Sprintf("%q", in[i])
	}
	return strings.Join(tmp, ", ")
}

func toStrings(in []extv1alpha1.PolicyCapability) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

// ---- status helpers (unchanged from imperative impl) ----

func (r *TenantReconciler) firstOpenBaoExtension(list *extv1alpha1.OpenBaoExtensionList) *extv1alpha1.OpenBaoExtension {
	if list == nil || len(list.Items) == 0 {
		return nil
	}
	return &list.Items[0]
}

func (r *TenantReconciler) patchStatus(ctx context.Context, ext *extv1alpha1.OpenBaoExtension) error {
	key := types.NamespacedName{Namespace: ext.GetNamespace(), Name: ext.GetName()}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var cur extv1alpha1.OpenBaoExtension
		if err := r.Get(ctx, key, &cur); err != nil {
			return err
		}
		orig := cur.DeepCopy()

		cur.Status.Conditions = ext.Status.Conditions
		utils.RecomputeReadyInPlace(&cur)

		return r.Status().Patch(ctx, &cur, client.MergeFrom(orig))
	})
}

func hasCondTrue(ext *extv1alpha1.OpenBaoExtension, t string) bool {
	for _, c := range ext.Status.Conditions {
		if c.Type == t && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}
