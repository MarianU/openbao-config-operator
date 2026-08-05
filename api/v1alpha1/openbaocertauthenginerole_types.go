// Adapted from redhat-cop/vault-config-operator
//
//	api/v1alpha1/certauthenginerole_types.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b
//	<https://github.com/redhat-cop/vault-config-operator>
//
// Licensed under the Apache License, Version 2.0
// <https://www.apache.org/licenses/LICENSE-2.0>.
//
// Modifications relative to upstream:
//   - Kind renamed CertAuthEngineRole → OpenBaoCertAuthEngineRole.
//   - spec.openbaoNamespace added; spec.authentication / spec.connection
//     removed.
//   - The certificate bundle MUST come from a Kubernetes Secret via
//     spec.certificateRef — never inline. PrepareInternalValues
//     resolves it into the bao-wire payload at reconcile time so a
//     secret rotation triggers a re-write on the next reconcile.
//
// OpenBaoCertAuthEngineRole owns a single trusted-cert role at
// auth/<spec.path>/certs/<spec.name>. The bundle field carries a
// PEM-encoded CA cert (or chain) bao trusts; allow-lists narrow what
// SAN/CN values successful clients may present; tokenPolicies is the
// list bao grants on a successful login.
package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject"
)

var _ vaultobject.VaultObject = &OpenBaoCertAuthEngineRole{}
var _ vaultobject.ConditionsAware = &OpenBaoCertAuthEngineRole{}
var _ vaultobject.WriteTracker = &OpenBaoCertAuthEngineRole{}
var _ vaultobject.RenameTracker = &OpenBaoCertAuthEngineRole{}

func (d *OpenBaoCertAuthEngineRole) BaoName() string {
	raw := d.Spec.Name
	if raw == "" {
		raw = d.Name
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func (d *OpenBaoCertAuthEngineRole) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

func (d *OpenBaoCertAuthEngineRole) GetPath() string {
	return "auth/" + strings.Trim(d.Spec.Path, "/") + "/certs/" + d.BaoName()
}

func (d *OpenBaoCertAuthEngineRole) GetPayload() map[string]interface{} {
	return nil
}

// IsEquivalentToDesiredState compares spec against the bao read.
// Slice fields are sorted before compare (bao stores them as sets);
// the certificate body is compared verbatim — bao normalises PEM
// whitespace to a canonical form on read.
func (d *OpenBaoCertAuthEngineRole) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	cur, ok := payload["role"].(*baoclient.CertAuthRoleSpec)
	if !ok || cur == nil {
		return false
	}
	if strings.TrimSpace(d.Status.ResolvedCertificate) != strings.TrimSpace(cur.Certificate) {
		return false
	}
	if d.Spec.DisplayName != cur.DisplayName {
		return false
	}
	if !sortedEqual(d.Spec.AllowedNames, cur.AllowedNames) {
		return false
	}
	if !sortedEqual(d.Spec.AllowedCommonNames, cur.AllowedCommonNames) {
		return false
	}
	if !sortedEqual(d.Spec.AllowedDNSSANs, cur.AllowedDNSSANs) {
		return false
	}
	if !sortedEqual(d.Spec.AllowedEmailSANs, cur.AllowedEmailSANs) {
		return false
	}
	if !sortedEqual(d.Spec.AllowedURISANs, cur.AllowedURISANs) {
		return false
	}
	if !sortedEqual(d.Spec.AllowedOrganizations, cur.AllowedOrganizations) {
		return false
	}
	if !sortedEqual(d.Spec.RequiredExtensions, cur.RequiredExtensions) {
		return false
	}
	if !sortedEqual(d.Spec.TokenPolicies, cur.TokenPolicies) {
		return false
	}
	if !sortedEqual(d.Spec.TokenBoundCIDRs, cur.TokenBoundCIDRs) {
		return false
	}
	desiredTTL := strings.TrimSpace(d.Spec.TokenTTL)
	if desiredTTL != "" && desiredTTL != cur.TokenTTL {
		return false
	}
	desiredMaxTTL := strings.TrimSpace(d.Spec.TokenMaxTTL)
	if desiredMaxTTL != "" && desiredMaxTTL != cur.TokenMaxTTL {
		return false
	}
	desiredPeriod := strings.TrimSpace(d.Spec.TokenPeriod)
	if desiredPeriod != "" && desiredPeriod != cur.TokenPeriod {
		return false
	}
	return true
}

func (d *OpenBaoCertAuthEngineRole) IsInitialized() bool { return true }

func (d *OpenBaoCertAuthEngineRole) IsDeletable() bool {
	return d.Spec.DeletionPolicy.DeletesGrantKind()
}

// PrepareInternalValues resolves spec.certificateRef into the bao-wire
// certificate body. Reads the named Secret, extracts the configured
// key, and stamps it onto status.ResolvedCertificate so ToBaoSpec
// (and the drift comparator) can use it without re-reading.
func (d *OpenBaoCertAuthEngineRole) PrepareInternalValues(ctx context.Context, object client.Object) error {
	if d.Spec.CertificateRef == nil {
		return fmt.Errorf("spec.certificateRef must reference a Secret containing the trusted CA bundle (PEM)")
	}
	//nolint:staticcheck // untyped context key matches upstream VCO contract
	cl, ok := ctx.Value("kubeClient").(client.Client)
	if !ok || cl == nil {
		return fmt.Errorf("kube client not available in reconcile context")
	}
	secNS := strings.TrimSpace(d.Spec.CertificateRef.Namespace)
	if secNS == "" {
		secNS = d.Namespace
	}
	secName := strings.TrimSpace(d.Spec.CertificateRef.Name)
	if secName == "" {
		return fmt.Errorf("spec.certificateRef.name must not be empty")
	}
	key := d.Spec.CertificateRef.Key
	if key == "" {
		key = "ca.crt"
	}
	var sec corev1.Secret
	if err := cl.Get(ctx, types.NamespacedName{Namespace: secNS, Name: secName}, &sec); err != nil {
		return fmt.Errorf("loading certificate Secret %s/%s: %w", secNS, secName, err)
	}
	body, ok := sec.Data[key]
	if !ok {
		return fmt.Errorf("Secret %s/%s has no key %q (the trusted CA bundle is required)",
			secNS, secName, key)
	}
	if len(body) == 0 {
		return fmt.Errorf("Secret %s/%s key %q is empty (the trusted CA bundle is required)",
			secNS, secName, key)
	}
	d.Status.ResolvedCertificate = string(body)
	return nil
}

func (d *OpenBaoCertAuthEngineRole) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoCertAuthEngineRole) IsValid() (bool, error) {
	if d.BaoName() == "" {
		return false, fmt.Errorf("spec.name (or metadata.name) must not be empty")
	}
	if strings.TrimSpace(d.Spec.Path) == "" {
		return false, fmt.Errorf("spec.path must name a cert auth mount")
	}
	if d.Spec.CertificateRef == nil {
		return false, fmt.Errorf("spec.certificateRef must reference a Secret containing the trusted CA bundle")
	}
	if strings.TrimSpace(d.Spec.CertificateRef.Name) == "" {
		return false, fmt.Errorf("spec.certificateRef.name must not be empty")
	}
	return true, nil
}

func (d *OpenBaoCertAuthEngineRole) ToBaoSpec() baoclient.CertAuthRoleSpec {
	return baoclient.CertAuthRoleSpec{
		Certificate:          d.Status.ResolvedCertificate,
		DisplayName:          d.Spec.DisplayName,
		AllowedNames:         append([]string(nil), d.Spec.AllowedNames...),
		AllowedCommonNames:   append([]string(nil), d.Spec.AllowedCommonNames...),
		AllowedDNSSANs:       append([]string(nil), d.Spec.AllowedDNSSANs...),
		AllowedEmailSANs:     append([]string(nil), d.Spec.AllowedEmailSANs...),
		AllowedURISANs:       append([]string(nil), d.Spec.AllowedURISANs...),
		AllowedOrganizations: append([]string(nil), d.Spec.AllowedOrganizations...),
		RequiredExtensions:   append([]string(nil), d.Spec.RequiredExtensions...),
		TokenPolicies:        append([]string(nil), d.Spec.TokenPolicies...),
		TokenTTL:             d.Spec.TokenTTL,
		TokenMaxTTL:          d.Spec.TokenMaxTTL,
		TokenPeriod:          d.Spec.TokenPeriod,
		TokenBoundCIDRs:      append([]string(nil), d.Spec.TokenBoundCIDRs...),
	}
}

// CertSecretRef points at a Kubernetes Secret containing the PEM
// certificate bundle.
type CertSecretRef struct {
	// Name of the Secret holding the trusted CA bundle.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace of the Secret. Defaults to this CR's namespace when
	// empty.
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`

	// Key within the Secret that holds the PEM bundle. Defaults to
	// "ca.crt" when empty.
	// +kubebuilder:validation:Optional
	Key string `json:"key,omitempty"`
}

// OpenBaoCertAuthEngineRoleSpec defines the desired state.
type OpenBaoCertAuthEngineRoleSpec struct {
	// DeletionPolicy controls what happens to the bao-side cert entry
	// when this CR is deleted or its bao identity changes. Delete
	// (the default) removes it, so new logins through it stop; tokens
	// already issued keep working until their TTL expires. Retain
	// releases the CR without touching bao — the entry survives as an
	// intentional, logged orphan that no CR tracks afterward; use
	// only where rendering churn must never drop live access.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// Path is the bao-side cert auth mount (e.g. "cert"). Pairs
	// with an OpenBaoAuthMethod of type=cert at the same path.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Path string `json:"path"`

	// Name is the bao-side role name (the cert entry name). Defaults
	// to metadata.name.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name,omitempty"`

	// OpenBaoNamespace targets a specific OpenBao namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// CertificateRef points at a Kubernetes Secret containing the
	// trusted CA bundle in PEM form. Required — bao rejects a cert
	// auth role with no certificate.
	// +kubebuilder:validation:Required
	CertificateRef *CertSecretRef `json:"certificateRef"`

	// DisplayName is bao's free-form label for the cert entry.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=512
	DisplayName string `json:"displayName,omitempty"`

	// AllowedNames is a glob-pattern allow-list bao matches against
	// the SAN-or-CN of the presented client cert. Empty means no
	// filter on this dimension.
	// +kubebuilder:validation:Optional
	AllowedNames []string `json:"allowedNames,omitempty"`

	// AllowedCommonNames restricts presented certs by Subject CN.
	// +kubebuilder:validation:Optional
	AllowedCommonNames []string `json:"allowedCommonNames,omitempty"`

	// AllowedDNSSANs restricts presented certs by DNS SAN.
	// +kubebuilder:validation:Optional
	AllowedDNSSANs []string `json:"allowedDnsSans,omitempty"`

	// AllowedEmailSANs restricts presented certs by email SAN.
	// +kubebuilder:validation:Optional
	AllowedEmailSANs []string `json:"allowedEmailSans,omitempty"`

	// AllowedURISANs restricts presented certs by URI SAN.
	// +kubebuilder:validation:Optional
	AllowedURISANs []string `json:"allowedUriSans,omitempty"`

	// AllowedOrganizations restricts presented certs by Subject
	// Organisation (O) attribute.
	// +kubebuilder:validation:Optional
	AllowedOrganizations []string `json:"allowedOrganizations,omitempty"`

	// RequiredExtensions narrows the cert by required X.509
	// extension OIDs.
	// +kubebuilder:validation:Optional
	RequiredExtensions []string `json:"requiredExtensions,omitempty"`

	// TokenPolicies is the list of bao policies granted on a
	// successful login with this cert.
	// +kubebuilder:validation:Optional
	TokenPolicies []string `json:"tokenPolicies,omitempty"`

	// TokenTTL / TokenMaxTTL / TokenPeriod are bao duration strings.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	TokenTTL string `json:"tokenTtl,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	TokenMaxTTL string `json:"tokenMaxTtl,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	TokenPeriod string `json:"tokenPeriod,omitempty"`

	// TokenBoundCIDRs restricts the source IPs of subsequent uses of
	// the issued token.
	// +kubebuilder:validation:Optional
	TokenBoundCIDRs []string `json:"tokenBoundCidrs,omitempty"`
}

// OpenBaoCertAuthEngineRoleStatus defines the observed state.
type OpenBaoCertAuthEngineRoleStatus struct {
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
	// +optional
	LastWrittenPath string `json:"lastWrittenPath,omitempty"`

	// ResolvedCertificate is the PEM bundle PrepareInternalValues
	// pulled from spec.certificateRef. Surfaced for visibility +
	// drift comparison; not user-settable directly.
	// +optional
	ResolvedCertificate string `json:"resolvedCertificate,omitempty"`
}

func (m *OpenBaoCertAuthEngineRole) GetConditions() []metav1.Condition  { return m.Status.Conditions }
func (m *OpenBaoCertAuthEngineRole) SetConditions(c []metav1.Condition) { m.Status.Conditions = c }
func (m *OpenBaoCertAuthEngineRole) IsBaoWritten() bool                 { return m.Status.BaoWritten }
func (m *OpenBaoCertAuthEngineRole) MarkBaoWritten()                    { m.Status.BaoWritten = true }
func (m *OpenBaoCertAuthEngineRole) LastWrittenBaoName() string         { return m.Status.LastWrittenBaoName }
func (m *OpenBaoCertAuthEngineRole) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}
func (m *OpenBaoCertAuthEngineRole) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obcar

// OpenBaoCertAuthEngineRole is the Schema for the
// openbaocertauthengineroles API.
type OpenBaoCertAuthEngineRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoCertAuthEngineRoleSpec   `json:"spec,omitempty"`
	Status OpenBaoCertAuthEngineRoleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoCertAuthEngineRoleList contains a list of
// OpenBaoCertAuthEngineRole.
type OpenBaoCertAuthEngineRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoCertAuthEngineRole `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoCertAuthEngineRole{}, &OpenBaoCertAuthEngineRoleList{})
}
