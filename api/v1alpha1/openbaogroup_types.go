// Adapted from redhat-cop/vault-config-operator
//
//	api/v1alpha1/group_types.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b
//	<https://github.com/redhat-cop/vault-config-operator>
//
// Licensed under the Apache License, Version 2.0
// <https://www.apache.org/licenses/LICENSE-2.0>.
//
// Modifications relative to upstream:
//   - Kind renamed Group → OpenBaoGroup.
//   - spec.openbaoNamespace added (X-Vault-Namespace target);
//     spec.authentication and spec.connection removed.
//   - Status.GroupID stamps the bao-side group id on first create so
//     OpenBaoGroupAlias can reference it without a redundant Read.
//   - IsEquivalentToDesiredState sorts policies / member id slices
//     before compare; type=external groups omit member fields from
//     drift comparison because bao silently drops them server-side.
//   - IsValid rejects empty names and policies/members on external
//     groups (bao would silently drop them; surface as Invalid so
//     the user notices).
//
// OpenBaoGroup owns a single identity group at identity/group. Bao
// upserts by (id, name); reads at identity/group/name/<name>. Groups
// hold a policy list (always) plus member entities/groups (internal
// only) or aliases (external only — managed by OpenBaoGroupAlias).
package v1alpha1

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject"
)

// Group type strings as bao expects them on the wire.
const (
	GroupTypeInternal = "internal"
	GroupTypeExternal = "external"
)

var _ vaultobject.VaultObject = &OpenBaoGroup{}
var _ vaultobject.ConditionsAware = &OpenBaoGroup{}
var _ vaultobject.WriteTracker = &OpenBaoGroup{}
var _ vaultobject.RenameTracker = &OpenBaoGroup{}

// BaoName returns the group name as bao stores it. spec.name takes
// precedence over metadata.name when set.
func (d *OpenBaoGroup) BaoName() string {
	raw := d.Spec.Name
	if raw == "" {
		raw = d.Name
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func (d *OpenBaoGroup) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

// EffectiveType returns the bao-wire group type, defaulting to
// "internal" when the spec leaves it unset. Centralised so the
// drift comparator and the BaoWrite path agree on the same default.
func (d *OpenBaoGroup) EffectiveType() string {
	t := strings.ToLower(strings.TrimSpace(d.Spec.Type))
	if t == "" {
		return GroupTypeInternal
	}
	return t
}

// GetPath returns the bao-side path for collision messages and logs.
// The wrapper routes through dedicated methods, not this string.
func (d *OpenBaoGroup) GetPath() string {
	return "identity/group/name/" + d.BaoName()
}

// GetPayload is unused by the comparator (it works against the typed
// IdentityGroup read shape); returning nil keeps the interface
// satisfied without producing a drift signal.
func (d *OpenBaoGroup) GetPayload() map[string]interface{} {
	return nil
}

// IsEquivalentToDesiredState compares the bao read against the spec.
// Slice fields are sorted because bao stores them as sets. type=external
// groups skip member-id fields because bao drops them on write.
func (d *OpenBaoGroup) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	cur, ok := payload["group"].(*baoclient.IdentityGroup)
	if !ok || cur == nil {
		return false
	}
	if d.EffectiveType() != strings.ToLower(strings.TrimSpace(cur.Type)) {
		return false
	}
	if !sortedEqual(d.Spec.Policies, cur.Policies) {
		return false
	}
	if d.EffectiveType() == GroupTypeInternal {
		if !sortedEqual(d.Spec.MemberGroupIds, cur.MemberGroupIDs) {
			return false
		}
		if !sortedEqual(d.Spec.MemberEntityIds, cur.MemberEntityIDs) {
			return false
		}
	}
	if !reflect.DeepEqual(stringMapOrNil(d.Spec.Metadata), stringMapOrNil(cur.Metadata)) {
		return false
	}
	return true
}

func sortedEqual(a, b []string) bool {
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	if len(aa) == 0 && len(bb) == 0 {
		return true
	}
	return reflect.DeepEqual(aa, bb)
}

func stringMapOrNil(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	return m
}

func (d *OpenBaoGroup) IsInitialized() bool { return true }
func (d *OpenBaoGroup) IsDeletable() bool   { return true }

func (d *OpenBaoGroup) PrepareInternalValues(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoGroup) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

// IsValid catches spec-level invariants that kubebuilder markers can't
// express compactly. Defense in depth on top of admission.
func (d *OpenBaoGroup) IsValid() (bool, error) {
	if d.BaoName() == "" {
		return false, fmt.Errorf("spec.name (or metadata.name) must not be empty")
	}
	t := d.EffectiveType()
	if t != GroupTypeInternal && t != GroupTypeExternal {
		return false, fmt.Errorf("spec.type %q is not valid; must be %q or %q",
			d.Spec.Type, GroupTypeInternal, GroupTypeExternal)
	}
	if t == GroupTypeExternal && (len(d.Spec.MemberGroupIds) > 0 || len(d.Spec.MemberEntityIds) > 0) {
		// Bao silently drops member ids on external groups — surface as
		// Invalid so the user fixes the spec rather than seeing a
		// permanently-Ready CR with no members.
		return false, fmt.Errorf("type=external groups must not set spec.memberGroupIds or spec.memberEntityIds; "+
			"members of external groups come from OpenBaoGroupAlias entries (got %d groupIds, %d entityIds)",
			len(d.Spec.MemberGroupIds), len(d.Spec.MemberEntityIds))
	}
	return true, nil
}

// ToBaoSpec materializes the bao-wire payload from the CR.
func (d *OpenBaoGroup) ToBaoSpec() baoclient.IdentityGroupSpec {
	spec := baoclient.IdentityGroupSpec{
		ID:       d.Status.GroupID,
		Name:     d.BaoName(),
		Type:     d.EffectiveType(),
		Policies: append([]string(nil), d.Spec.Policies...),
		Metadata: copyStringMapV1(d.Spec.Metadata),
	}
	if d.EffectiveType() == GroupTypeInternal {
		spec.MemberGroupIDs = append([]string(nil), d.Spec.MemberGroupIds...)
		spec.MemberEntityIDs = append([]string(nil), d.Spec.MemberEntityIds...)
	}
	return spec
}

func copyStringMapV1(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// OpenBaoGroupSpec defines the desired state of OpenBaoGroup.
type OpenBaoGroupSpec struct {
	// Name is the bao-side group name. Defaults to metadata.name.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name,omitempty"`

	// OpenBaoNamespace targets a specific OpenBao namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// Type selects the bao group kind: "internal" (default) or
	// "external". Internal groups hold member entities and member
	// groups directly. External groups receive members through
	// OpenBaoGroupAlias entries that map auth-method aliases into
	// the group. Type is immutable on bao's side — changing it on
	// an existing group surfaces as Ready=False with reason=BaoError;
	// delete and recreate the CR to switch.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=internal;external
	Type string `json:"type,omitempty"`

	// Policies is the list of bao policy names attached to the
	// group. Every member of the group inherits these policies.
	// +kubebuilder:validation:Optional
	Policies []string `json:"policies,omitempty"`

	// MemberGroupIds is the list of bao group ids whose members
	// inherit this group's policies. Only meaningful for
	// type=internal groups; external groups must leave this empty.
	// +kubebuilder:validation:Optional
	MemberGroupIds []string `json:"memberGroupIds,omitempty"`

	// MemberEntityIds is the list of bao entity ids that belong to
	// this group. Only meaningful for type=internal groups; external
	// groups must leave this empty.
	// +kubebuilder:validation:Optional
	MemberEntityIds []string `json:"memberEntityIds,omitempty"`

	// Metadata is a free-form key/value map persisted on the bao
	// group. Useful for cross-system correlation. Keys and values
	// must be ASCII strings.
	// +kubebuilder:validation:Optional
	Metadata map[string]string `json:"metadata,omitempty"`
}

// OpenBaoGroupStatus defines the observed state of OpenBaoGroup.
type OpenBaoGroupStatus struct {
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// +optional
	BaoWritten bool `json:"baoWritten,omitempty"`
	// +optional
	LastWrittenBaoName string `json:"lastWrittenBaoName,omitempty"`
	// +optional
	LastWrittenOpenBaoNamespace string `json:"lastWrittenOpenBaoNamespace,omitempty"`

	// GroupID is the bao-side group id stamped on first create. Other
	// CRs (notably OpenBaoGroupAlias) reference it as canonicalId
	// when binding to this group.
	// +optional
	GroupID string `json:"groupId,omitempty"`
}

func (m *OpenBaoGroup) GetConditions() []metav1.Condition  { return m.Status.Conditions }
func (m *OpenBaoGroup) SetConditions(c []metav1.Condition) { m.Status.Conditions = c }
func (m *OpenBaoGroup) IsBaoWritten() bool                 { return m.Status.BaoWritten }
func (m *OpenBaoGroup) MarkBaoWritten()                    { m.Status.BaoWritten = true }
func (m *OpenBaoGroup) LastWrittenBaoName() string         { return m.Status.LastWrittenBaoName }
func (m *OpenBaoGroup) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}
func (m *OpenBaoGroup) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obg

// OpenBaoGroup is the Schema for the openbaogroups API. Reconciles a CR
// to a bao-side identity group.
type OpenBaoGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoGroupSpec   `json:"spec,omitempty"`
	Status OpenBaoGroupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoGroupList contains a list of OpenBaoGroup.
type OpenBaoGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoGroup `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoGroup{}, &OpenBaoGroupList{})
}
