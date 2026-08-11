// Adapted from redhat-cop/vault-config-operator
//
//	api/v1alpha1/certauthengineconfig_types.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b
//	<https://github.com/redhat-cop/vault-config-operator>
//
// Licensed under the Apache License, Version 2.0
// <https://www.apache.org/licenses/LICENSE-2.0>.
//
// Modifications relative to upstream:
//   - Kind renamed CertAuthEngineConfig → OpenBaoCertAuthEngineConfig.
//   - spec.openbaoNamespace added; spec.authentication / spec.connection
//     removed.
//   - Pairs with an OpenBaoAuthMethod of type=cert at spec.path. The
//     auth-method controller is responsible for mount lifecycle; this
//     CRD only writes auth/<mount>/config.
//
// OpenBaoCertAuthEngineConfig owns the bao-side mount-level configuration
// of a cert auth method at auth/<spec.path>/config: OCSP cache settings,
// identity-alias metadata, etc. Per-cert trust + role bindings live on
// OpenBaoCertAuthEngineRole.
package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	baoclient "github.com/stakater-ab/openbao-config-operator/internal/client"
	"github.com/stakater-ab/openbao-config-operator/internal/vaultobject"
)

var _ vaultobject.VaultObject = &OpenBaoCertAuthEngineConfig{}
var _ vaultobject.ConditionsAware = &OpenBaoCertAuthEngineConfig{}
var _ vaultobject.WriteTracker = &OpenBaoCertAuthEngineConfig{}
var _ vaultobject.RenameTracker = &OpenBaoCertAuthEngineConfig{}

// BaoName returns the bao-side cert auth mount path. Cert auth config
// is mount-singleton, so the "name" is just the mount path.
func (d *OpenBaoCertAuthEngineConfig) BaoName() string {
	return strings.Trim(d.Spec.Path, "/")
}

func (d *OpenBaoCertAuthEngineConfig) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

func (d *OpenBaoCertAuthEngineConfig) GetPath() string {
	return "auth/" + strings.Trim(d.Spec.Path, "/") + "/config"
}

func (d *OpenBaoCertAuthEngineConfig) GetPayload() map[string]interface{} {
	return nil
}

// IsEquivalentToDesiredState compares pointer fields directly:
// nil-on-spec means "adopt bao value" so a CR that doesn't pin a
// field doesn't false-positive on bao defaults. Empty bao values are
// treated as nil for the same reason.
func (d *OpenBaoCertAuthEngineConfig) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	cur, ok := payload["config"].(*baoclient.CertAuthConfigSpec)
	if !ok || cur == nil {
		return false
	}
	if !boolPtrEq(d.Spec.DisableBinding, cur.DisableBinding) {
		return false
	}
	if !boolPtrEq(d.Spec.EnableIdentityAliasMetadata, cur.EnableIdentityAliasMetadata) {
		return false
	}
	if !intPtrEq(d.Spec.OCSPCacheSize, cur.OCSPCacheSize) {
		return false
	}
	if !boolPtrEq(d.Spec.OCSPFailOpen, cur.OCSPFailOpen) {
		return false
	}
	if !boolPtrEq(d.Spec.OCSPQueryAllServers, cur.OCSPQueryAllServers) {
		return false
	}
	return true
}

func boolPtrEq(desired, current *bool) bool {
	if desired == nil {
		// Spec leaves field unset → adopt bao's value.
		return true
	}
	if current == nil {
		return false
	}
	return *desired == *current
}

func intPtrEq(desired, current *int) bool {
	if desired == nil {
		return true
	}
	if current == nil {
		return false
	}
	return *desired == *current
}

func (d *OpenBaoCertAuthEngineConfig) IsInitialized() bool { return true }

// IsDeletable returns false: bao's auth/<mount>/config has no DELETE
// endpoint — config persists with the mount. Removing the CR releases
// the finalizer without touching bao.
func (d *OpenBaoCertAuthEngineConfig) IsDeletable() bool { return false }

func (d *OpenBaoCertAuthEngineConfig) PrepareInternalValues(ctx context.Context, object client.Object) error {
	return nil
}
func (d *OpenBaoCertAuthEngineConfig) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoCertAuthEngineConfig) IsValid() (bool, error) {
	if strings.TrimSpace(d.Spec.Path) == "" {
		return false, fmt.Errorf("spec.path must name a cert auth mount")
	}
	return true, nil
}

func (d *OpenBaoCertAuthEngineConfig) ToBaoSpec() baoclient.CertAuthConfigSpec {
	return baoclient.CertAuthConfigSpec{
		DisableBinding:              d.Spec.DisableBinding,
		EnableIdentityAliasMetadata: d.Spec.EnableIdentityAliasMetadata,
		OCSPCacheSize:               d.Spec.OCSPCacheSize,
		OCSPFailOpen:                d.Spec.OCSPFailOpen,
		OCSPQueryAllServers:         d.Spec.OCSPQueryAllServers,
	}
}

// OpenBaoCertAuthEngineConfigSpec defines the desired state.
type OpenBaoCertAuthEngineConfigSpec struct {
	// Path is the bao-side cert auth mount path (e.g. "cert").
	// Pairs with an OpenBaoAuthMethod of type=cert at the same path.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Path string `json:"path"`

	// OpenBaoNamespace targets a specific OpenBao namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// DisableBinding turns off cert binding to a specific identity
	// alias.
	// +kubebuilder:validation:Optional
	DisableBinding *bool `json:"disableBinding,omitempty"`

	// EnableIdentityAliasMetadata controls whether bao copies the
	// cert subject + serial onto the identity alias metadata.
	// +kubebuilder:validation:Optional
	EnableIdentityAliasMetadata *bool `json:"enableIdentityAliasMetadata,omitempty"`

	// OCSPCacheSize sets the cache size (in entries) for the OCSP
	// response cache. Bao's default is 100.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	OCSPCacheSize *int `json:"ocspCacheSize,omitempty"`

	// OCSPFailOpen treats unreachable OCSP responders as a successful
	// validation when true. Defaults to bao's setting (typically false).
	// +kubebuilder:validation:Optional
	OCSPFailOpen *bool `json:"ocspFailOpen,omitempty"`

	// OCSPQueryAllServers queries every OCSP responder in parallel
	// rather than the first that responds.
	// +kubebuilder:validation:Optional
	OCSPQueryAllServers *bool `json:"ocspQueryAllServers,omitempty"`
}

// OpenBaoCertAuthEngineConfigStatus defines the observed state.
type OpenBaoCertAuthEngineConfigStatus struct {
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

func (m *OpenBaoCertAuthEngineConfig) GetConditions() []metav1.Condition  { return m.Status.Conditions }
func (m *OpenBaoCertAuthEngineConfig) SetConditions(c []metav1.Condition) { m.Status.Conditions = c }
func (m *OpenBaoCertAuthEngineConfig) IsBaoWritten() bool                 { return m.Status.BaoWritten }
func (m *OpenBaoCertAuthEngineConfig) MarkBaoWritten()                    { m.Status.BaoWritten = true }
func (m *OpenBaoCertAuthEngineConfig) LastWrittenBaoName() string         { return m.Status.LastWrittenBaoName }
func (m *OpenBaoCertAuthEngineConfig) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}
func (m *OpenBaoCertAuthEngineConfig) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obcac

// OpenBaoCertAuthEngineConfig is the Schema for the
// openbaocertauthengineconfigs API.
type OpenBaoCertAuthEngineConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoCertAuthEngineConfigSpec   `json:"spec,omitempty"`
	Status OpenBaoCertAuthEngineConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoCertAuthEngineConfigList contains a list of
// OpenBaoCertAuthEngineConfig.
type OpenBaoCertAuthEngineConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoCertAuthEngineConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoCertAuthEngineConfig{}, &OpenBaoCertAuthEngineConfigList{})
}
