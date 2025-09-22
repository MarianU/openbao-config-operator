// +kubebuilder:rbac:groups=tenantoperator.stakater.com,resources=tenants,verbs=get;list;watch
// +kubebuilder:rbac:groups=tenantoperator.stakater.com,resources=tenants/status,verbs=get
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoextensions,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaoextensions/status,verbs=get;update;patch

package tenant

import (
	"context"
	"fmt"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	mto "github.com/stakater-ab/tenant-operator/api/v1beta3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	extv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	"github.com/stakater-ab/mto-extension-openbao/internal/constants"

	// internal utils
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	utils "github.com/stakater-ab/mto-extension-openbao/internal/utils"
)

type TenantReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Log       logr.Logger
	baoClient baoclient.Client

	kvMount   string // e.g., "secret"
	authMount string // e.g., "kubernetes"
	env       string // e.g., "prod"
}

func NewTenantReconciler(mgr ctrl.Manager) (*TenantReconciler, error) {
	addr, ok := os.LookupEnv("VAULT_ADDR")
	if !ok || addr == "" {
		addr = os.Getenv("BAO_ADDR")
	}
	token, ok := os.LookupEnv("VAULT_TOKEN")
	if !ok || token == "" {
		token = os.Getenv("BAO_TOKEN")
	}
	if addr == "" || token == "" {
		return nil, fmt.Errorf("set VAULT_ADDR/VAULT_TOKEN (or BAO_ADDR/BAO_TOKEN)")
	}

	return &TenantReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Log:       ctrl.Log.WithName("controller").WithName("Tenant"),
		baoClient: baoclient.NewHTTPClient(addr, token),
		kvMount:   constants.DefaultKVMount,
		authMount: constants.DefaultAuthMount,
		env:       constants.DefaultEnv,
	}, nil
}

func (r *TenantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("tenant", req.Name)

	var t mto.Tenant
	if err := r.Get(ctx, req.NamespacedName, &t); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	ten := t.GetName()

	var extList extv1alpha1.OpenBaoExtensionList
	_ = r.List(ctx, &extList)

	// Best-effort: get (first) OpenBaoExtension to read status from.
	ext := r.firstOpenBaoExtension(&extList)

	// Hard gate: do not touch OpenBao or write status until AuthConfigured=True.
	// This prevents racing ClusterAuth and eliminates a large class of conflicts.
	if ext == nil || !hasCondTrue(ext, extv1alpha1.CondAuthConfigured) {
		// Do NOT write any status here. Just requeue briefly.
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// We'll publish exactly one status update at the end.
	finalStatus := metav1.ConditionTrue
	finalReason := extv1alpha1.ReasonSuccess
	finalMessage := "All tenants reconciled."
	defer func() {
		if ext == nil {
			return
		}
		utils.RemoveCondGen(ext, extv1alpha1.CondTenantsReconciled)
		utils.SetCondGen(ext, extv1alpha1.CondTenantsReconciled, finalStatus, finalReason, finalMessage)
		_ = r.patchStatus(ctx, ext) // conflict-safe after we change patchStatus below
	}()

	ok, err := r.baoClient.CheckKVv2Mount(ctx, r.kvMount)
	if err != nil {
		log.Error(err, "utils mount check failed", "mount", r.kvMount)
		finalStatus = metav1.ConditionFalse
		finalReason = extv1alpha1.ReasonError
		finalMessage = err.Error()
		return ctrl.Result{}, err
	}
	if !ok {
		err := fmt.Errorf("kv-v2 mount %q not present or not v2", r.kvMount)
		log.Error(err, "precondition failed")
		finalStatus = metav1.ConditionFalse
		finalReason = extv1alpha1.ReasonError
		finalMessage = err.Error()
		return ctrl.Result{}, err
	}

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
	if len(wanted) == 0 {
		finalStatus = metav1.ConditionTrue
		finalReason = extv1alpha1.ReasonSuccess
		finalMessage = "No namespaces for tenant."
		return ctrl.Result{}, nil
	}

	okAuth, err := r.baoClient.CheckAuthMount(ctx, r.authMount)
	if err != nil {
		log.Error(err, "utils auth-mount check failed", "authMount", r.authMount)
		finalStatus = metav1.ConditionFalse
		finalReason = extv1alpha1.ReasonError
		finalMessage = err.Error()
		return ctrl.Result{}, err
	}
	if !okAuth {
		err := fmt.Errorf("kubernetes auth mount %q not found or wrong type; enable it or set OPENBAO_AUTH_MOUNT", r.authMount)
		finalStatus = metav1.ConditionFalse
		finalReason = extv1alpha1.ReasonError
		finalMessage = err.Error()
		return ctrl.Result{}, err
	}

	// compute editorCaps once
	var editorCaps []string
	{
		var spec *extv1alpha1.OpenBaoExtensionSpec
		if len(extList.Items) > 0 {
			spec = &extList.Items[0].Spec
		}
		editorCaps = effectiveCaps(spec, "editor")
	}

	for _, it := range wanted {
		nsFull := utils.NamespaceFull(ten, it.short, it.withPrefix)
		polName := utils.PolicyNameEditor(ten, nsFull)
		roleName := utils.RoleName(ten, nsFull)
		polBody := buildKVv2NamespacePolicy(r.kvMount, ten, r.env, nsFull, editorCaps)

		// Create/update policy
		if err := r.baoClient.UpsertPolicy(ctx, polName, polBody); err != nil {
			log.Error(err, "failed to upsert policy", "policy", polName)
			finalStatus = metav1.ConditionFalse
			finalReason = extv1alpha1.ReasonError
			finalMessage = err.Error()
			return ctrl.Result{}, err
		}

		// Defaults from OpenBaoExtension.spec.rbac.token (already fetched in extList)
		var tokenTTL, tokenMaxTTL string
		var tokenRenewable *bool
		if len(extList.Items) > 0 {
			ext0 := extList.Items[0]
			tokenTTL = leaseString(ext0.Spec.RBAC.Token.TTL)
			tokenMaxTTL = leaseString(ext0.Spec.RBAC.Token.MaxTTL)
			if ext0.Spec.RBAC.Token.Renewable != nil {
				tokenRenewable = ext0.Spec.RBAC.Token.Renewable
			}
		}

		// Upsert kubernetes auth role
		spec := baoclient.K8sRoleSpec{
			Policies:                      []string{polName},
			BoundServiceAccountNames:      []string{"default"},
			BoundServiceAccountNamespaces: []string{nsFull},
			TokenTTL:                      tokenTTL,
			TokenMaxTTL:                   tokenMaxTTL,
			Renewable:                     tokenRenewable,
		}
		if err := r.baoClient.UpsertK8sRole(ctx, r.authMount, roleName, spec); err != nil {
			log.Error(err, "failed to upsert k8s auth role", "role", roleName)
			finalStatus = metav1.ConditionFalse
			finalReason = extv1alpha1.ReasonError
			finalMessage = err.Error()
			return ctrl.Result{}, err
		}

		log.Info("ensured tenant namespace artifacts", "nsFull", nsFull, "policy", polName, "role", roleName)
	}

	return ctrl.Result{}, nil
}

func (r *TenantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mto.Tenant{}).
		Complete(r)
}

// format as "<secs>s" which Vault/OpenBao accepts (e.g., "3600s")
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

// --- policyOverrides helpers (minimal) ---

// Operator "built-ins" when no overrides are provided.
var builtinCaps = map[string][]string{
	"admin":  {"create", "read", "update", "delete", "list"},
	"editor": {"create", "read", "update", "list"},
	"viewer": {"read", "list"},
}

// Compute effective capabilities for a tier from spec (overrides replace built-ins).
// Also enforces safety.allowDeletes=false by stripping "delete".
func effectiveCaps(spec *extv1alpha1.OpenBaoExtensionSpec, tier string) []string {
	base := builtinCaps[tier]
	caps := append([]string(nil), base...)

	// Guard both spec and the pointer field
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

	// Safety gate (value struct; zero == false)
	allowDeletes := false
	if spec != nil {
		allowDeletes = spec.Safety.AllowDeletes
	}
	if !allowDeletes {
		caps = filterOut(caps, "delete")
	}
	return dedupeKeepOrder(caps)
}

// Build a kv-v2 policy body for the namespace scope using the given capabilities.
// - Data paths: create/update/read; delete only if present in caps.
// - Metadata paths: read; list if present in caps.
// We do NOT grant metadata delete here.
func buildKVv2NamespacePolicy(kvMount, tenant, env, nsFull string, caps []string) string {
	prefix := fmt.Sprintf("tenants/%s/%s/%s", strings.ToLower(tenant), env, nsFull)
	has := func(verb string) bool { return contains(caps, verb) }

	var b strings.Builder

	// data/*
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

	// metadata/*
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
		// Allow listing the parent prefix for UX
		if has("list") {
			fmt.Fprintf(&b, "path \"%s/metadata/%s\" {\n  capabilities = [\"list\"]\n}\n\n",
				kvMount, prefix)
		}
	}

	return b.String()
}

func filterOut(in []string, forbid string) []string {
	out := in[:0]
	for _, v := range in {
		if v != forbid {
			out = append(out, v)
		}
	}
	return append([]string(nil), out...)
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

// ---- status helpers ----

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

		// Replace conditions from the ext passed in (which has our mutations)
		cur.Status.Conditions = ext.Status.Conditions
		// If you rely on a Ready rollup, recompute here (or keep it owned by ClusterAuth).
		utils.RecomputeReadyInPlace(&cur)

		return r.Status().Patch(ctx, &cur, client.MergeFrom(orig))
	})
}

// hasCondTrue returns true if .status.conditions contains {Type: t, Status: True}.
func hasCondTrue(ext *extv1alpha1.OpenBaoExtension, t string) bool {
	for _, c := range ext.Status.Conditions {
		if c.Type == t && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}
