// Adapted from redhat-cop/vault-config-operator
//
//	api/v1alpha1/policy_types.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b
//
// Apache-2.0 — see THIRD_PARTY_NOTICES.md at repo root.
//
// Modified:
//   - spec.authentication removed (operator uses OpenBaoExtension's token).
//   - spec.connection removed (same reason).
//   - spec.type defaulted to "acl"; legacy /sys/policy/<name> path not supported.
//   - PrepareInternalValues: accessor templating deferred to Story 6; currently rejects
//     CRs whose spec.policy contains ${auth/<mount>/@accessor}.
//   - IsEquivalentToDesiredState simplified: always compares {"policy": body}
//     since we only target sys/policies/acl/ (the modern endpoint).
//   - GetPath simplified: always sys/policies/acl/<name> (our bao client builds the URL).
//   - Fixed upstream copy-paste bug on line 37 (ConditionsAware assertion pointed at
//     PKISecretEngineRole instead of Policy).
//   - GetKubeAuthConfiguration / GetVaultConnection return nil — our operator
//     uses a single token from OpenBaoExtension.
package v1alpha1

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject"
)

var _ vaultobject.VaultObject = &Policy{}
var _ vaultobject.ConditionsAware = &Policy{}

func (d *Policy) GetVaultConnection() *vaultobject.VaultConnection {
	// Stripped field; our operator uses OpenBaoExtension's connection.
	return nil
}

func (d *Policy) GetKubeAuthConfiguration() *vaultobject.KubeAuthConfiguration {
	// Stripped field; our operator uses OpenBaoExtension's token.
	return nil
}

// BaoName returns the policy name as it will be written to OpenBao.
// If spec.name is set it takes precedence; otherwise metadata.name is used.
func (d *Policy) BaoName() string {
	if d.Spec.Name != "" {
		return d.Spec.Name
	}
	return d.Name
}

func (d *Policy) GetPath() string {
	return vaultobject.CleansePath("sys/policies/acl/" + d.BaoName())
}

func (d *Policy) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"policy": d.Spec.Policy,
	}
}

func (d *Policy) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	return reflect.DeepEqual(d.GetPayload(), payload)
}

func (d *Policy) IsInitialized() bool {
	return true
}

func (d *Policy) IsDeletable() bool {
	return true
}

// PrepareInternalValues rejects CRs that use VCO's ${auth/<mount>/@accessor}
// templating syntax. Our bao client does not yet expose the sys/auth listing
// required to resolve these placeholders; support is tracked for Story 6.
func (d *Policy) PrepareInternalValues(ctx context.Context, object client.Object) error {
	if strings.Contains(d.Spec.Policy, "${auth/") {
		return fmt.Errorf("accessor templating (${auth/<mount>/@accessor}) not supported in this release; " +
			"hardcode the accessor UUID or track support via Story 6")
	}
	return nil
}

func (d *Policy) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

func (r *Policy) IsValid() (bool, error) {
	return true, nil
}

// PolicySpec defines the desired state of Policy.
type PolicySpec struct {
	// Policy is an OpenBao policy body expressed in HCL.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Policy string `json:"policy"`

	// Type of the policy. Only "acl" is supported.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum={"acl"}
	// +kubebuilder:default:="acl"
	Type string `json:"type,omitempty"`

	// Name of the policy as stored in OpenBao. Takes precedence over
	// metadata.name when set. Must match OpenBao's policy naming rules.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`[a-z0-9]([-a-z0-9]*[a-z0-9])?`
	Name string `json:"name,omitempty"`
}

// PolicyStatus defines the observed state of Policy.
type PolicyStatus struct {
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

func (m *Policy) GetConditions() []metav1.Condition {
	return m.Status.Conditions
}

func (m *Policy) SetConditions(conditions []metav1.Condition) {
	m.Status.Conditions = conditions
}

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
