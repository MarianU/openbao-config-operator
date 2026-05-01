// Adapted from redhat-cop/vault-config-operator
//
//	api/v1alpha1/identityoidcrole_types.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b
//	<https://github.com/redhat-cop/vault-config-operator>
//
// Licensed under the Apache License, Version 2.0
// <https://www.apache.org/licenses/LICENSE-2.0>.
//
// Modifications relative to upstream:
//   - Kind renamed to OpenBaoIdentityTokenRole.
//   - spec.openbaoNamespace added; spec.authentication / spec.connection
//     removed (operator uses OpenBaoExtension's single token).
//   - IsValid rejects empty key — bao silently rejects role writes
//     where the named OIDC key does not exist, but surfacing as Invalid
//     keeps the user from a permanently flapping CR.
//   - IsEquivalentToDesiredState normalizes TTL: bao stores TTL as int
//     seconds; the wrapper renders <n>s for stable round-trips so a
//     spec of "1h" doesn't false-positive against bao's 3600.
//
// OpenBaoIdentityTokenRole owns a single role at
// identity/oidc/role/<name>. Roles bind a name to an OIDC key (managed
// out of band today) and a JWT claims template. Used to mint OIDC ID
// tokens for federated auth (e.g. tenants pulling AWS / GCP creds via
// OIDC trust).
package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject"
)

var _ vaultobject.VaultObject = &OpenBaoIdentityTokenRole{}
var _ vaultobject.ConditionsAware = &OpenBaoIdentityTokenRole{}
var _ vaultobject.WriteTracker = &OpenBaoIdentityTokenRole{}
var _ vaultobject.RenameTracker = &OpenBaoIdentityTokenRole{}

func (d *OpenBaoIdentityTokenRole) BaoName() string {
	raw := d.Spec.Name
	if raw == "" {
		raw = d.Name
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func (d *OpenBaoIdentityTokenRole) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

func (d *OpenBaoIdentityTokenRole) GetPath() string {
	return "identity/oidc/role/" + d.BaoName()
}

func (d *OpenBaoIdentityTokenRole) GetPayload() map[string]interface{} {
	return nil
}

// IsEquivalentToDesiredState normalises TTL on both sides because bao
// returns int-seconds for ttl which the wrapper renders as <n>s.
func (d *OpenBaoIdentityTokenRole) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	cur, ok := payload["role"].(*baoclient.IdentityTokenRoleSpec)
	if !ok || cur == nil {
		return false
	}
	if strings.TrimSpace(d.Spec.Key) != cur.Key {
		return false
	}
	if d.Spec.Template != cur.Template {
		return false
	}
	if d.Spec.ClientID != cur.ClientID {
		return false
	}
	desiredTTL := strings.TrimSpace(d.Spec.TTL)
	currentTTL := cur.TTL
	if desiredTTL == "" {
		// Spec leaves TTL unset → adopt bao's value (no drift).
		return true
	}
	return desiredTTL == currentTTL
}

func (d *OpenBaoIdentityTokenRole) IsInitialized() bool { return true }
func (d *OpenBaoIdentityTokenRole) IsDeletable() bool   { return true }

func (d *OpenBaoIdentityTokenRole) PrepareInternalValues(ctx context.Context, object client.Object) error {
	return nil
}
func (d *OpenBaoIdentityTokenRole) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoIdentityTokenRole) IsValid() (bool, error) {
	if d.BaoName() == "" {
		return false, fmt.Errorf("spec.name (or metadata.name) must not be empty")
	}
	if strings.TrimSpace(d.Spec.Key) == "" {
		return false, fmt.Errorf("spec.key must name a pre-existing OIDC key at identity/oidc/key/<key>")
	}
	return true, nil
}

func (d *OpenBaoIdentityTokenRole) ToBaoSpec() baoclient.IdentityTokenRoleSpec {
	return baoclient.IdentityTokenRoleSpec{
		Key:      strings.TrimSpace(d.Spec.Key),
		Template: d.Spec.Template,
		ClientID: d.Spec.ClientID,
		TTL:      strings.TrimSpace(d.Spec.TTL),
	}
}

// OpenBaoIdentityTokenRoleSpec defines the desired state.
type OpenBaoIdentityTokenRoleSpec struct {
	// Name is the bao-side role name. Defaults to metadata.name.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name,omitempty"`

	// OpenBaoNamespace targets a specific OpenBao namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// Key names a pre-existing OIDC key at identity/oidc/key/<key>
	// that signs the issued tokens. The key must already exist —
	// the controller does not create OIDC keys today.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`

	// Template is the JWT claims template applied to issued tokens.
	// Bao accepts plain JSON or base64-wrapped JSON; the value is
	// passed through verbatim. Templating tokens are documented at
	// https://openbao.org/docs/secrets/identity/identity-token/.
	// +kubebuilder:validation:Optional
	Template string `json:"template,omitempty"`

	// ClientID is the audience claim ("aud") of issued tokens. Set
	// to the IAM role / GCP service account / external relier that
	// will validate the tokens.
	// +kubebuilder:validation:Optional
	ClientID string `json:"clientId,omitempty"`

	// TTL is a bao duration string ("1h", "3600s", "30m"). When
	// empty bao uses the key's default TTL.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	TTL string `json:"ttl,omitempty"`
}

// OpenBaoIdentityTokenRoleStatus defines the observed state.
type OpenBaoIdentityTokenRoleStatus struct {
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
}

func (m *OpenBaoIdentityTokenRole) GetConditions() []metav1.Condition  { return m.Status.Conditions }
func (m *OpenBaoIdentityTokenRole) SetConditions(c []metav1.Condition) { m.Status.Conditions = c }
func (m *OpenBaoIdentityTokenRole) IsBaoWritten() bool                 { return m.Status.BaoWritten }
func (m *OpenBaoIdentityTokenRole) MarkBaoWritten()                    { m.Status.BaoWritten = true }
func (m *OpenBaoIdentityTokenRole) LastWrittenBaoName() string         { return m.Status.LastWrittenBaoName }
func (m *OpenBaoIdentityTokenRole) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}
func (m *OpenBaoIdentityTokenRole) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obitr

// OpenBaoIdentityTokenRole is the Schema for the
// openbaoidentitytokenroles API.
type OpenBaoIdentityTokenRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoIdentityTokenRoleSpec   `json:"spec,omitempty"`
	Status OpenBaoIdentityTokenRoleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoIdentityTokenRoleList contains a list of OpenBaoIdentityTokenRole.
type OpenBaoIdentityTokenRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoIdentityTokenRole `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoIdentityTokenRole{}, &OpenBaoIdentityTokenRoleList{})
}
