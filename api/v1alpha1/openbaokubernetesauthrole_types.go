// Adapted from redhat-cop/vault-config-operator
//
//	api/v1alpha1/kubernetesauthenginerole_types.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b
//	api/v1alpha1/utils/commons.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b (TargetNamespaceConfig)
//	<https://github.com/redhat-cop/vault-config-operator>
//
// Licensed under the Apache License, Version 2.0
// <https://www.apache.org/licenses/LICENSE-2.0>.
//
// Modifications from upstream — non-obvious behavior changes only;
// pure WHAT items (which fields/methods are absent, which types are
// co-located) are visible from reading the file.
//
//   - Kind renamed from KubernetesAuthEngineRole → OpenBaoKubernetesAuthRole
//     and relocated from api/vco/v1alpha1 to api/v1alpha1 to consolidate
//     the operator's API surface in one package. ADR-0003 records the
//     decision.
//   - spec.openbaoNamespace added: routes the bao API call to a specific
//     OpenBao namespace via the X-Vault-Namespace header. Upstream models
//     this on spec.authentication.namespace; we hoisted it to spec because
//     spec.authentication is removed.
//   - spec.name Pattern anchored with ^…$ — OpenAPI v3's `pattern`
//     keyword does substring match by default; the unanchored upstream
//     regex accepts "Bad_Name1" because the substring "a" matches.
//   - IsValid rejects present-but-empty TargetNamespaces in addition
//     to upstream's XOR check: BaoGet treats an empty read as
//     "not found", so a request bao silently no-ops on would trap the
//     reconciler in an infinite create loop without this guard.
//   - IsEquivalentToDesiredState replaces reflect.DeepEqual with a
//     comparator that is order-insensitive on the list-shaped bao keys
//     — bao does not guarantee read ordering and naive equality
//     produces a 5-minute write storm whenever the read order drifts.
//   - status.baoWritten plus IsBaoWritten/MarkBaoWritten added: the
//     deletion path needs a durable signal to decide whether to call
//     BaoDelete, since condition history is transient (apiserver
//     compaction, etcd backup restore) and rolling back a Ready=True
//     to False after a successful write must not leak the bao role.
package v1alpha1

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stakater/openbao-config-operator/internal/vaultobject"
)

// NoNamespacePlaceholder is the sentinel value the controller writes to
// bound_service_account_namespaces when a label selector resolves to
// zero matching namespaces. Bao rejects an empty list outright with a
// 400; the sentinel keeps the role write succeeding so the namespace
// watch can rebind the role as soon as a matching namespace appears.
// Visible in `bao read auth/<mount>/role/<name>` as a hint to operators
// that the role is currently effectively unbound.
const NoNamespacePlaceholder = "__no_namespace__"

// kaerBaoNameRe is the post-normalization shape we require for any name
// written to bao. Mirrors the +kubebuilder:validation:Pattern marker on
// spec.name; kept here as a runtime guard because IsValid runs after
// BaoName() normalization (TrimSpace + ToLower) and admission may have
// been bypassed (stale CRD on the cluster, fake client in unit tests,
// metadata.name with spaces somehow). Anchored with ^…$ for the same
// substring-match reason the marker is.
//
// Renamed from baoNameRe to kaerBaoNameRe to avoid collision with any
// other type's regex in this package.
var kaerBaoNameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

var _ vaultobject.VaultObject = &OpenBaoKubernetesAuthRole{}
var _ vaultobject.ConditionsAware = &OpenBaoKubernetesAuthRole{}
var _ vaultobject.WriteTracker = &OpenBaoKubernetesAuthRole{}

// BaoName returns the role name as it will be written to OpenBao.
// If spec.name is set it takes precedence; otherwise metadata.name is used.
//
// Defense in depth: kubebuilder Pattern + DNS-1123 already enforce a
// lowercased shape at admission. Normalizing again here means a stale
// CRD on the cluster, an envtest with markers stripped, or direct Go
// construction in a unit test can't slip a "Foo " through and produce
// a bao-side name that doesn't round-trip through GetK8sRole.
func (d *OpenBaoKubernetesAuthRole) BaoName() string {
	raw := d.Spec.Name
	if raw == "" {
		raw = d.Name
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

// OpenBaoNamespace returns the bao namespace this CR's API calls target.
// Empty string means the root namespace, matching the X-Vault-Namespace
// header semantics: absent header = root, present header = scoped.
func (d *OpenBaoKubernetesAuthRole) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

// GetPath returns the bao-side path for this role: auth/<mount>/role/<name>.
// The OpenBao namespace (if any) is applied by the controller via the
// X-Vault-Namespace header, not embedded into this path.
func (d *OpenBaoKubernetesAuthRole) GetPath() string {
	return vaultobject.CleansePath("auth/" + d.Spec.Path + "/role/" + d.BaoName())
}

// GetPayload returns the desired bao role state. Used by the shared base
// for drift detection and as the upsert body.
func (d *OpenBaoKubernetesAuthRole) GetPayload() map[string]interface{} {
	return d.Spec.VRole.toMap()
}

// kaerOrderInsensitiveListKeys are the bao-side payload keys whose values
// are list-shaped and whose read order is not guaranteed equal to the
// write order. Comparing them with reflect.DeepEqual would see false
// drift on every reconcile after bao reordered the list, triggering a
// 5-minute write storm. CLAUDE.md primitive checklist requires the
// drift comparator to normalize ordering on every such field.
var kaerOrderInsensitiveListKeys = []string{
	"bound_service_account_namespaces",
	"bound_service_account_names",
	"token_policies",
	"token_bound_cidrs",
}

// IsEquivalentToDesiredState compares the desired payload against the
// current bao-side payload. The four list-shaped keys above are
// compared as sets (order-insensitive); all other fields use direct
// equality.
func (d *OpenBaoKubernetesAuthRole) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	desired := d.Spec.VRole.toMap()
	for _, key := range kaerOrderInsensitiveListKeys {
		if !equalUnorderedStringSlice(desired[key], payload[key]) {
			return false
		}
	}
	desiredRest := stripKeys(desired, kaerOrderInsensitiveListKeys...)
	currentRest := stripKeys(payload, kaerOrderInsensitiveListKeys...)
	return reflect.DeepEqual(desiredRest, currentRest)
}

func stripKeys(m map[string]interface{}, keys ...string) map[string]interface{} {
	skip := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		skip[k] = struct{}{}
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if _, drop := skip[k]; drop {
			continue
		}
		out[k] = v
	}
	return out
}

// equalUnorderedStringSlice returns true when a and b contain the same
// strings regardless of order. Inputs are accepted as `any` because
// payload maps store interface{} values; we coerce both sides to
// []string before comparing. nil and empty slices are treated as equal
// (bao writes the field but reads back nil when the list is empty).
func equalUnorderedStringSlice(a, b any) bool {
	as := coerceToStringSlice(a)
	bs := coerceToStringSlice(b)
	if len(as) != len(bs) {
		return false
	}
	ac := append([]string(nil), as...)
	bc := append([]string(nil), bs...)
	sort.Strings(ac)
	sort.Strings(bc)
	return reflect.DeepEqual(ac, bc)
}

func coerceToStringSlice(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case []string:
		return x
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func (d *OpenBaoKubernetesAuthRole) IsInitialized() bool {
	return true
}

func (d *OpenBaoKubernetesAuthRole) IsDeletable() bool {
	return d.Spec.DeletionPolicy.DeletesGrantKind()
}

// PrepareInternalValues resolves spec.targetNamespaces.targetNamespaceSelector
// to a concrete namespace list and stashes it on the unexported
// VRole.namespaces field for toMap() to read. Reads the kube client from
// ctx under the untyped key "kubeClient" — that's the upstream VCO
// convention and the shared base injects r.Client there immediately
// before calling this method.
//
// On a literal targetNamespaces list (no selector), no k8s lookup is
// needed and we copy the literal into the internal field directly.
//
// Failures here surface as Ready=False reason=InternalError because the
// shared base hardcodes ReasonInternalError for any PrepareInternalValues
// error — k8s apiserver failures aren't bao failures and shouldn't
// page on a BaoError dashboard.
func (d *OpenBaoKubernetesAuthRole) PrepareInternalValues(ctx context.Context, object client.Object) error {
	if d.Spec.TargetNamespaces.TargetNamespaceSelector != nil {
		names, err := d.findSelectedNamespaceNames(ctx)
		if err != nil {
			return err
		}
		if len(names) == 0 {
			// Bao rejects an empty bound_service_account_namespaces list;
			// the placeholder keeps the role write succeeding when the
			// selector matches nothing yet. Once a matching namespace
			// appears, the watch fires and the role rebinds.
			d.SetInternalNamespaces([]string{NoNamespacePlaceholder})
		} else {
			d.SetInternalNamespaces(names)
		}
		return nil
	}
	d.SetInternalNamespaces(append([]string(nil), d.Spec.TargetNamespaces.TargetNamespaces...))
	return nil
}

func (d *OpenBaoKubernetesAuthRole) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoKubernetesAuthRole) findSelectedNamespaceNames(ctx context.Context) ([]string, error) {
	selector, err := metav1.LabelSelectorAsSelector(d.Spec.TargetNamespaces.TargetNamespaceSelector)
	if err != nil {
		return nil, err
	}
	//nolint:staticcheck // untyped context key matches upstream VCO contract
	cl, ok := ctx.Value("kubeClient").(client.Client)
	if !ok || cl == nil {
		return nil, errors.New(`PrepareInternalValues: "kubeClient" missing from context — base must inject r.Client before calling`)
	}
	var nsList corev1.NamespaceList
	if err := cl.List(ctx, &nsList, &client.ListOptions{LabelSelector: selector}); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(nsList.Items))
	for i := range nsList.Items {
		out = append(out, nsList.Items[i].Name)
	}
	return out, nil
}

// IsValid runs spec-level validation that is too rich for kubebuilder
// markers. Failures classify as ReasonInvalid (no requeue).
func (d *OpenBaoKubernetesAuthRole) IsValid() (bool, error) {
	// Defense in depth on the bao-side name. The
	// +kubebuilder:validation:Pattern marker on spec.name applies to
	// the user-supplied value before normalization, but BaoName()
	// runs TrimSpace + ToLower and falls back to metadata.name. A CR
	// with metadata.name="FOO BAR" admits today (DNS-1123 rejects
	// spaces, but if the CRD validation was somehow bypassed — fake
	// client, stale CRD, schema-relaxed apply) the normalized value
	// still contains an internal space. Re-check the same anchored
	// regex against the normalized name so bao never receives garbage.
	if name := d.BaoName(); !kaerBaoNameRe.MatchString(name) {
		return false, fmt.Errorf("normalized bao name %q does not match %s — fix metadata.name or spec.name", name, kaerBaoNameRe)
	}

	hasSelector := d.Spec.TargetNamespaces.TargetNamespaceSelector != nil
	hasList := d.Spec.TargetNamespaces.TargetNamespaces != nil
	switch {
	case hasSelector && hasList:
		return false, errors.New("only one of spec.targetNamespaces.targetNamespaceSelector or spec.targetNamespaces.targetNamespaces can be specified")
	case !hasSelector && !hasList:
		return false, errors.New("one of spec.targetNamespaces.targetNamespaceSelector or spec.targetNamespaces.targetNamespaces must be specified")
	case hasList && len(d.Spec.TargetNamespaces.TargetNamespaces) == 0:
		// Defense in depth: kubebuilder MinItems=1 already rejects this
		// at admission, but a stale CRD or fake client can bypass it.
		// Without this check, the upsert succeeds with an empty list
		// and BaoGet's drift comparison treats the read as "not found",
		// trapping the controller in an infinite create loop.
		return false, errors.New("spec.targetNamespaces.targetNamespaces must not be empty when set")
	}
	return true, nil
}

// TargetNamespaceConfig selects the set of Kubernetes namespaces whose
// service accounts should bind to the bao role this CR creates.
// Exactly one of TargetNamespaceSelector or TargetNamespaces must be set;
// IsValid enforces the constraint with a friendly message because the
// XOR rule is too rich for OpenAPI's pattern keyword.
type TargetNamespaceConfig struct {
	// TargetNamespaceSelector matches namespaces by label. Re-resolved
	// on every reconcile and on every namespace label change (the
	// controller's Watches(&corev1.Namespace{}) fans out via mapFn).
	// +kubebuilder:validation:Optional
	TargetNamespaceSelector *metav1.LabelSelector `json:"targetNamespaceSelector,omitempty"`

	// TargetNamespaces is a literal list of namespace names. Static —
	// not re-resolved on namespace label change. Use this when the
	// namespace set is known at apply time and does not move.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	TargetNamespaces []string `json:"targetNamespaces,omitempty"`
}

// VRole carries the bao-side role fields. Inlined into the spec so the
// CRD shape matches upstream and existing VCO YAML manifests transfer
// with only the spec.connection / spec.authentication strip.
type VRole struct {
	// TargetServiceAccounts is the list of service accounts inside each
	// matched namespace whose tokens may exchange for a bao token via
	// this role. Default is "default" because that's the typical SA a
	// pod runs under absent explicit configuration.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:default={"default"}
	// +listType=set
	TargetServiceAccounts []string `json:"targetServiceAccounts"`

	// Audience is the JWT audience claim bao verifies on login.
	// Optional; bao defaults to no audience check when unset.
	// +kubebuilder:validation:Optional
	Audience string `json:"audience,omitempty"`

	// AliasNameSource controls how identity aliases are generated.
	// serviceaccount_uid is the safer choice (UIDs are unique and
	// non-reusable); serviceaccount_name lets you pre-create alias
	// records but conflates SA recreations with the same name.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum:={"serviceaccount_uid","serviceaccount_name"}
	// +kubebuilder:default="serviceaccount_uid"
	AliasNameSource string `json:"aliasNameSource,omitempty"`

	// TokenTTL is the bao-format duration string (e.g. "1h", "3600s",
	// or compound forms like "1h30m") for the incremental token
	// lifetime. Empty omits the field on upsert so bao falls back to
	// mount defaults. The Pattern requires explicit units (no bare
	// integers) so admission rejects typos like "1 hour" instead of
	// surfacing them as a bao 400 mid-reconcile.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	TokenTTL string `json:"tokenTTL,omitempty"`

	// Policies is the list of bao policy names this role binds.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	Policies []string `json:"policies"`

	// TokenMaxTTL caps token renewal lifetime. Bao-format duration
	// string (e.g. "24h", "86400s"). Empty omits the field on upsert.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	TokenMaxTTL string `json:"tokenMaxTTL,omitempty"`

	// TokenBoundCIDRs restricts which client IPs may use tokens issued
	// from this role.
	// +kubebuilder:validation:Optional
	// +listType=set
	TokenBoundCIDRs []string `json:"tokenBoundCIDRs,omitempty"`

	// TokenExplicitMaxTTL is a hard cap on token lifetime that ignores
	// renewals. Bao-format duration string. Empty omits the field.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	TokenExplicitMaxTTL string `json:"tokenExplicitMaxTTL,omitempty"`

	// TokenNoDefaultPolicy, when true, prevents bao from attaching its
	// "default" policy to tokens issued by this role. Pointer to
	// distinguish "leave at bao's default" from explicit false.
	// +kubebuilder:validation:Optional
	TokenNoDefaultPolicy *bool `json:"tokenNoDefaultPolicy,omitempty"`

	// TokenNumUses caps how many times a token may be used; 0 means
	// unlimited. Pointer because 0 is a meaningful explicit value
	// (override mount default) distinct from "leave at default".
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	TokenNumUses *int `json:"tokenNumUses,omitempty"`

	// TokenPeriod, if set, makes tokens issued from this role periodic
	// (renewable indefinitely as long as the period elapses). Bao-format
	// duration string. Empty omits the field.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	TokenPeriod string `json:"tokenPeriod,omitempty"`

	// TokenType is the kind of token (service / batch / default /
	// default-service / default-batch). Empty omits the field so bao
	// uses the mount-tuned default.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum:={"service","batch","default","default-service","default-batch"}
	// +kubebuilder:default="default"
	TokenType string `json:"tokenType,omitempty"`

	// namespaces is the resolved bound-namespace list, populated by
	// PrepareInternalValues from either the literal TargetNamespaces or
	// the selector-matched live namespace set. Excluded from JSON
	// (`json:"-"`) so it does not appear in the CRD schema.
	namespaces []string `json:"-"`
}

// SetInternalNamespaces is the setter PrepareInternalValues calls. The
// underlying field is unexported because nothing outside this package
// has a legitimate reason to write it directly; controllers obtain a
// resolved list through the Reconcile flow.
func (d *OpenBaoKubernetesAuthRole) SetInternalNamespaces(namespaces []string) {
	d.Spec.namespaces = namespaces
}

// BoundNamespaces returns the resolved bound-namespace list that
// PrepareInternalValues stashed on the unexported VRole field. The
// controller's toK8sRoleSpec uses it to populate the upsert payload
// without reaching into the unexported field across the package
// boundary.
func (d *OpenBaoKubernetesAuthRole) BoundNamespaces() []string {
	if d.Spec.namespaces == nil {
		return nil
	}
	return append([]string(nil), d.Spec.namespaces...)
}

// toMap shapes the desired state into the payload form bao stores. The
// emit predicates for tokenNumUses and tokenNoDefaultPolicy treat the
// bao defaults (0 and false) as "unset", omitting the key when the
// effective value matches the default. The reason is symmetry with the
// read-back payload: bao always echoes these fields with their default
// value on a role read, even when the upsert request never specified
// them. If toMap emitted "token_num_uses: 0" (because the user set
// *int = &0) but the read-side payload also emitted 0, fine — they
// match. If toMap omitted (user left it nil) but the read-side included
// 0, every periodic reconcile would see drift and re-upsert: a 5-minute
// write storm. Treating "explicit default" === "unset" === "default"
// keeps both sides agreeing.
//
// Caveat: a user who transitions from spec.tokenNumUses=&5 back to
// spec.tokenNumUses=nil cannot push the value back to bao's default
// without an explicit *int=&0 — UpsertK8sRole only emits the key when
// the pointer is non-nil and bao keeps the previously-stored value
// when the key is absent. This is a rare workflow; document on the
// CRD field and accept.
func (i *VRole) toMap() map[string]interface{} {
	payload := map[string]interface{}{
		"bound_service_account_names":      i.TargetServiceAccounts,
		"bound_service_account_namespaces": i.namespaces,
		"token_policies":                   i.Policies,
	}
	if i.AliasNameSource != "" {
		payload["alias_name_source"] = i.AliasNameSource
	}
	if i.Audience != "" {
		payload["audience"] = i.Audience
	}
	if i.TokenTTL != "" {
		payload["token_ttl"] = i.TokenTTL
	}
	if i.TokenMaxTTL != "" {
		payload["token_max_ttl"] = i.TokenMaxTTL
	}
	if len(i.TokenBoundCIDRs) > 0 {
		payload["token_bound_cidrs"] = i.TokenBoundCIDRs
	}
	if i.TokenExplicitMaxTTL != "" {
		payload["token_explicit_max_ttl"] = i.TokenExplicitMaxTTL
	}
	if i.TokenNoDefaultPolicy != nil && *i.TokenNoDefaultPolicy {
		payload["token_no_default_policy"] = true
	}
	if i.TokenNumUses != nil && *i.TokenNumUses != 0 {
		payload["token_num_uses"] = *i.TokenNumUses
	}
	if i.TokenPeriod != "" {
		payload["token_period"] = i.TokenPeriod
	}
	if i.TokenType != "" {
		payload["token_type"] = i.TokenType
	}
	return payload
}

// OpenBaoKubernetesAuthRoleSpec defines the desired state of
// OpenBaoKubernetesAuthRole.
type OpenBaoKubernetesAuthRoleSpec struct {
	// DeletionPolicy controls what happens to the bao-side role when
	// this CR is deleted or its bao identity changes. Delete (the
	// default) removes the role, so new logins through it stop;
	// tokens already issued keep working until their TTL expires.
	// Retain releases the CR without touching bao — the role survives
	// as an intentional, logged orphan that no CR tracks afterward;
	// use only where rendering churn must never drop live access.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// Path is the auth mount under which the role is created. The bao
	// path is auth/<path>/role/<name>. Plain string (not VCO's Path)
	// because we don't need the legacy regex VCO carries.
	//
	// The Pattern accepts nested mount paths (e.g. dev/k8s, k8s/cluster-a)
	// since bao supports them, but rejects whitespace, control chars,
	// and shell metacharacters at admission instead of letting them
	// surface as a bao 400 mid-reconcile. MaxLength=128 is well above
	// any realistic mount path while still bounding the request URL.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Path string `json:"path"`

	// VRole is the inline bao role payload. Keeping it inline matches
	// upstream so VCO YAML manifests transfer cleanly modulo the
	// spec.connection / spec.authentication strip.
	VRole `json:",inline"`

	// TargetNamespaces selects the set of Kubernetes namespaces whose
	// service accounts bind to this role.
	// +kubebuilder:validation:Required
	TargetNamespaces TargetNamespaceConfig `json:"targetNamespaces"`

	// Name overrides metadata.name when written to bao. Pattern is
	// anchored — OpenAPI v3's `pattern` keyword does substring match
	// by default, so an unanchored regex would accept "Bad_Name1"
	// because the substring "a" matches. MaxLength matches DNS-1123
	// (the conservative ceiling for k8s-style names).
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern:=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name,omitempty"`

	// OpenBaoNamespace targets a specific OpenBao namespace for this
	// role's API calls (sets the X-Vault-Namespace header). Empty (the
	// default) means the root namespace and matches pre-namespace-support
	// behaviour. Nested namespaces are allowed via slash-separated
	// segments (e.g. "acme/sub"); a trailing slash is accepted but not
	// required (bao accepts both forms).
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`
}

// OpenBaoKubernetesAuthRoleStatus defines the observed state.
type OpenBaoKubernetesAuthRoleStatus struct {
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// BaoWritten records whether this CR has ever successfully written
	// to OpenBao. The shared reconciler uses it on the deletion path
	// to decide whether to call BaoDelete; without a durable signal a
	// CR whose Ready flipped True→False (e.g. token lost capability)
	// before deletion would silently leak the bao role.
	// +optional
	BaoWritten bool `json:"baoWritten,omitempty"`

	// LastWrittenBaoName captures the role name the controller last
	// successfully wrote. The next reconcile compares this against
	// the current BaoName(); a mismatch means the user renamed via
	// spec.name and the controller deletes the previous bao role
	// before recording the new identity.
	// +optional
	LastWrittenBaoName string `json:"lastWrittenBaoName,omitempty"`

	// LastWrittenOpenBaoNamespace captures the OpenBao namespace the
	// controller last wrote into. Combined with LastWrittenBaoName
	// forms the full identity tuple.
	// +optional
	LastWrittenOpenBaoNamespace string `json:"lastWrittenOpenBaoNamespace,omitempty"`
}

func (m *OpenBaoKubernetesAuthRole) GetConditions() []metav1.Condition {
	return m.Status.Conditions
}

func (m *OpenBaoKubernetesAuthRole) SetConditions(conditions []metav1.Condition) {
	m.Status.Conditions = conditions
}

func (m *OpenBaoKubernetesAuthRole) IsBaoWritten() bool { return m.Status.BaoWritten }
func (m *OpenBaoKubernetesAuthRole) MarkBaoWritten()    { m.Status.BaoWritten = true }

func (m *OpenBaoKubernetesAuthRole) LastWrittenBaoName() string {
	return m.Status.LastWrittenBaoName
}

func (m *OpenBaoKubernetesAuthRole) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}

func (m *OpenBaoKubernetesAuthRole) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obkar

// OpenBaoKubernetesAuthRole is the Schema for the openbaokubernetesauthroles
// API. Reconciled against OpenBao auth/<path>/role/<name>.
type OpenBaoKubernetesAuthRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoKubernetesAuthRoleSpec   `json:"spec,omitempty"`
	Status OpenBaoKubernetesAuthRoleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoKubernetesAuthRoleList contains a list of OpenBaoKubernetesAuthRole.
type OpenBaoKubernetesAuthRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoKubernetesAuthRole `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoKubernetesAuthRole{}, &OpenBaoKubernetesAuthRoleList{})
}
