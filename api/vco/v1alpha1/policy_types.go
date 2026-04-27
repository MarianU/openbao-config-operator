// Adapted from redhat-cop/vault-config-operator
//
//	api/v1alpha1/policy_types.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b
//
// Apache-2.0 — see THIRD_PARTY_NOTICES.md at repo root.
//
// Modified:
//   - spec.authentication and spec.connection removed (operator uses
//     OpenBaoExtension's single token).
//   - GetKubeAuthConfiguration / GetVaultConnection methods removed; they
//     return nil and are not part of our slimmer VaultObject interface.
//   - spec.type removed (only "acl" is supported and GetPath always emits
//     sys/policies/acl/<name>; the field was decoration).
//   - Any "${...}" placeholder in spec.policy is rejected by IsValid. HCL
//     policy bodies do not legitimately use shell-style interpolation; the
//     deny is broad because every form we have seen (auth/identity/pki) is
//     a VCO-style placeholder this controller does not resolve. Lives in
//     IsValid (spec-level invalid → stable error, no requeue) rather than
//     PrepareInternalValues (would requeue every 30s on user error).
//   - IsEquivalentToDesiredState whitespace-tolerant — drops naive DeepEqual
//     to avoid a 5-minute write-storm when bao normalizes the policy body.
//   - spec.name pattern anchored with ^…$ — OpenAPI v3 `pattern` does
//     substring match by default; upstream's unanchored regex accepts
//     "Bad_Name1" because the substring "a" matches.
//   - Fixed upstream copy-paste bug in the ConditionsAware type-assertion
//     declaration (upstream's `var _ vaultutils.ConditionsAware =
//     &PKISecretEngineRole{}` was wrong; should reference Policy).
package v1alpha1

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject"
)

// vcoPlaceholderRe matches `${<word>/...}` — a VCO mount-style placeholder.
// The trailing slash after the mount name is what distinguishes these from
// bao's own ACL templating (`${identity.entity.name}`, dotted paths).
var vcoPlaceholderRe = regexp.MustCompile(`\$\{[a-z][a-z0-9_-]*/`)

var _ vaultobject.VaultObject = &Policy{}
var _ vaultobject.ConditionsAware = &Policy{}

// BaoName returns the policy name as it will be written to OpenBao.
// If spec.name is set it takes precedence; otherwise metadata.name is used.
//
// Defense in depth: the kubebuilder Pattern marker on spec.name and DNS-1123
// rules on metadata.name already enforce a lowercased, trimmed shape at
// admission. Normalizing again here means a stale CRD on the cluster, an
// envtest with markers stripped, or direct Go construction in a unit test
// can't slip a "Foo " through and produce a bao-side name that doesn't
// round-trip through GetPolicy.
func (d *Policy) BaoName() string {
	raw := d.Spec.Name
	if raw == "" {
		raw = d.Name
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func (d *Policy) GetPath() string {
	return vaultobject.CleansePath("sys/policies/acl/" + d.BaoName())
}

func (d *Policy) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"policy": d.Spec.Policy,
	}
}

// IsEquivalentToDesiredState compares the desired payload against the
// current bao-side payload, tolerant to whitespace normalization OpenBao
// applies on round-trip. A naive reflect.DeepEqual here causes a
// write-storm: if the server strips a trailing newline, every periodic
// reconcile sees "drift" and re-PUTs the policy.
func (d *Policy) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	desired := strings.TrimSpace(d.Spec.Policy)
	current := ""
	if v, ok := payload["policy"]; ok {
		if s, ok := v.(string); ok {
			current = strings.TrimSpace(s)
		}
	}
	return desired == current
}

func (d *Policy) IsInitialized() bool {
	return true
}

func (d *Policy) IsDeletable() bool {
	return true
}

// PrepareInternalValues is a no-op for Policy. Spec validation lives in
// IsValid (correctly classified as a spec problem, not a server-side
// problem) so the base does not waste reconciles requeueing on user error.
func (d *Policy) PrepareInternalValues(ctx context.Context, object client.Object) error {
	return nil
}

func (d *Policy) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

// IsValid runs spec-level validation that is too rich for kubebuilder
// markers. Failures classify as ReasonInvalid (no requeue) so the user
// sees a stable error in CR status rather than a flapping retry.
func (r *Policy) IsValid() (bool, error) {
	// Defense in depth: kubebuilder MinLength=1 already rejects empty
	// spec.policy at admission, but a stale CRD on the cluster or a fake
	// k8s client in unit tests can bypass that. The shared reconciler
	// treats an empty bao read as "missing" and would otherwise enter an
	// infinite create loop.
	if strings.TrimSpace(r.Spec.Policy) == "" {
		return false, fmt.Errorf("spec.policy must not be empty")
	}
	// Deny VCO-style mount placeholders specifically — `${<mount>/...}`
	// where the slash distinguishes them from bao's own ACL templating
	// (`${identity.entity.name}`, `{{identity.entity.id}}`) which uses
	// dotted paths and is valid policy text. Any `${<word>/` is a VCO
	// placeholder this controller does not resolve; pass-through would
	// either be rejected at write time or produce a broken ACL at
	// evaluation time.
	if vcoPlaceholderRe.MatchString(r.Spec.Policy) {
		return false, fmt.Errorf(
			`spec.policy contains a mount-prefix placeholder ("${<mount>/...}"); ` +
				`this controller does not resolve them. Substitute the literal value — ` +
				`e.g. for an auth accessor: bao auth list -format=json | jq -r '.["<mount>/"].accessor'.`)
	}
	return true, nil
}

// PolicySpec defines the desired state of Policy.
type PolicySpec struct {
	// Policy is an OpenBao policy body expressed in HCL.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Policy string `json:"policy"`

	// Name of the policy as stored in OpenBao. Takes precedence over
	// metadata.name when set. Must match OpenBao's policy naming rules.
	// Pattern is anchored — OpenAPI v3's `pattern` keyword does substring
	// match by default, so an unanchored regex would accept "Bad_Name1"
	// because the substring "a" matches.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name,omitempty"`
}

// PolicyStatus defines the observed state of Policy.
type PolicyStatus struct {
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// BaoWritten records whether this CR has ever successfully written to
	// OpenBao. Once set true it is never cleared. The shared reconciler
	// uses it on the deletion path to decide whether to call BaoDelete:
	// without a durable signal we have to fall back to "is Ready=True
	// right now", which incorrectly skips cleanup when Ready flipped
	// True→False (e.g. token lost capability) before the user deleted
	// the CR, leaving an orphan.
	// +optional
	BaoWritten bool `json:"baoWritten,omitempty"`
}

func (m *Policy) GetConditions() []metav1.Condition {
	return m.Status.Conditions
}

func (m *Policy) SetConditions(conditions []metav1.Condition) {
	m.Status.Conditions = conditions
}

func (m *Policy) IsBaoWritten() bool { return m.Status.BaoWritten }
func (m *Policy) MarkBaoWritten()    { m.Status.BaoWritten = true }

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced

// Policy is the Schema for the policies API.
type Policy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicySpec   `json:"spec,omitempty"`
	Status PolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PolicyList contains a list of Policy.
type PolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Policy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Policy{}, &PolicyList{})
}
