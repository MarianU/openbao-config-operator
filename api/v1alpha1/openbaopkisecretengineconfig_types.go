// Adapted from redhat-cop/vault-config-operator
//   api/v1alpha1/pkisecretengineconfig_types.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b
//   <https://github.com/redhat-cop/vault-config-operator>
//
// Licensed under the Apache License, Version 2.0
// <https://www.apache.org/licenses/LICENSE-2.0>.
//
// Modifications relative to upstream:
//   - Kind renamed PKISecretEngineConfig → OpenBaoPKISecretEngineConfig.
//   - Trimmed to root CA generation only — pkiType=root is the single
//     supported value (single-step CA generation via
//     /root/generate/internal). The PKIType enum is open for additive
//     extension so other generation flavours can be added without
//     breaking root-only consumers.
//   - spec.openbaoNamespace added (X-Vault-Namespace target);
//     spec.authentication and spec.connection removed (operator uses
//     a single token from OpenBaoExtension).
//   - IsDeletable returns false (see below); the rename-cleanup path
//     skips BaoDeleteIdentity for the same reason.
//   - status.phase / status.caSerialNumber capture the bootstrap
//     state machine; status.lastWrittenBaoName /
//     status.lastWrittenOpenBaoNamespace track the bao identity for
//     rename detection.
//
// OpenBaoPKISecretEngineConfig owns the per-mount PKI configuration:
// generates the CA at <path>/root/generate/internal and writes the URL
// distribution config at <path>/config/urls. Pairs with an existing
// OpenBaoSecretEngine of kind=pki at the same spec.path — the mount
// itself is enabled by that other CR; this one populates it.
//
// IsDeletable returns false: deleting the CR must not call BaoDelete
// because there is no bao API to "remove" a CA — disabling the PKI
// mount destroys the private key and silently invalidates every cert
// ever issued by it. The shared base supports this opt-out: on CR
// delete the finalizer is released without touching bao, and the
// rename-cleanup path skips BaoDeleteIdentity for the same reason.
package v1alpha1

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject"
)

var _ vaultobject.VaultObject = &OpenBaoPKISecretEngineConfig{}
var _ vaultobject.ConditionsAware = &OpenBaoPKISecretEngineConfig{}
var _ vaultobject.WriteTracker = &OpenBaoPKISecretEngineConfig{}
var _ vaultobject.RenameTracker = &OpenBaoPKISecretEngineConfig{}

// PhaseActive is the only steady-state phase emitted in the root-only
// release. Intermediate-CA support adds AwaitingExternalSignature.
const PhaseActive = "Active"

// BaoName returns the canonical bao identity for this CR — the PKI
// mount path the CA + URLs live under. Trimmed of slashes.
func (d *OpenBaoPKISecretEngineConfig) BaoName() string {
	return strings.Trim(d.Spec.Path, "/")
}

// OpenBaoNamespace returns the bao namespace this CR's API calls
// target. Empty = root.
func (d *OpenBaoPKISecretEngineConfig) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

// GetPath is the synthetic identifier used in collision messages and
// log lines. Distinct from spec.path because logs distinguish a
// PKIConfig at "pki" from a PKIRole at "pki" by their kind.
func (d *OpenBaoPKISecretEngineConfig) GetPath() string {
	return "pki/config/" + d.BaoName()
}

// GetPayload is unused by the controller's drift comparator —
// IsEquivalentToDesiredState reads from the comparator's payload arg
// directly. Kept on the interface so the type satisfies VaultObject.
func (d *OpenBaoPKISecretEngineConfig) GetPayload() map[string]interface{} {
	return nil
}

// IsEquivalentToDesiredState compares the bao-side read against the
// CR's spec. Once a CA is active, the only mutable surface is the URL
// config — the CA cert itself is locked because regenerating it would
// destroy the private key. Comparison is order-insensitive on the URL
// slices because bao stores them as sets.
func (d *OpenBaoPKISecretEngineConfig) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	caExists, _ := payload["caExists"].(bool)
	if !caExists {
		return false
	}
	desiredURLs := normalizePKIURLs(d.Spec.URLs)
	currentURLs, _ := payload["urls"].(map[string][]string)
	currentURLs = sortAndCopyURLs(currentURLs)
	return reflect.DeepEqual(desiredURLs, currentURLs)
}

func normalizePKIURLs(in *PKIURLs) map[string][]string {
	out := map[string][]string{
		"issuingCertificates":   nil,
		"crlDistributionPoints": nil,
		"ocspServers":           nil,
	}
	if in == nil {
		return out
	}
	out["issuingCertificates"] = sortedCopy(in.IssuingCertificates)
	out["crlDistributionPoints"] = sortedCopy(in.CRLDistributionPoints)
	out["ocspServers"] = sortedCopy(in.OCSPServers)
	return out
}

func sortAndCopyURLs(in map[string][]string) map[string][]string {
	out := map[string][]string{
		"issuingCertificates":   nil,
		"crlDistributionPoints": nil,
		"ocspServers":           nil,
	}
	if in == nil {
		return out
	}
	for k := range out {
		out[k] = sortedCopy(in[k])
	}
	return out
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

func (d *OpenBaoPKISecretEngineConfig) IsInitialized() bool {
	return true
}

// IsDeletable returns false. See package doc — disabling a PKI mount
// loses the private key irreversibly.
func (d *OpenBaoPKISecretEngineConfig) IsDeletable() bool {
	return false
}

func (d *OpenBaoPKISecretEngineConfig) PrepareInternalValues(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoPKISecretEngineConfig) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

// IsValid validates spec-level invariants. Pattern markers + Required
// catch the structural cases at admission; this catches what those
// can't (whitespace-only commonName, kvV2-style placeholder traps if
// any are added later).
func (d *OpenBaoPKISecretEngineConfig) IsValid() (bool, error) {
	if strings.TrimSpace(d.Spec.Path) == "" {
		return false, fmt.Errorf("spec.path must not be empty")
	}
	if strings.TrimSpace(d.Spec.CommonName) == "" {
		return false, fmt.Errorf("spec.commonName must not be empty")
	}
	if d.Spec.PKIType != "root" {
		return false, fmt.Errorf("spec.pkiType=%q is not supported; only \"root\" is implemented", d.Spec.PKIType)
	}
	return true, nil
}

// PKISubject groups the X.509 subject fields other than CommonName.
// Each field is a slice because bao accepts multi-valued RDNs (e.g.
// multiple OUs). Empty slices are dropped before being sent to bao.
type PKISubject struct {
	// +kubebuilder:validation:Optional
	Country []string `json:"country,omitempty"`
	// +kubebuilder:validation:Optional
	Locality []string `json:"locality,omitempty"`
	// +kubebuilder:validation:Optional
	Province []string `json:"province,omitempty"`
	// +kubebuilder:validation:Optional
	StreetAddress []string `json:"streetAddress,omitempty"`
	// +kubebuilder:validation:Optional
	PostalCode []string `json:"postalCode,omitempty"`
	// +kubebuilder:validation:Optional
	Organization []string `json:"organization,omitempty"`
	// +kubebuilder:validation:Optional
	OU []string `json:"ou,omitempty"`
}

// PKIURLs are the CA-access points published in every issued cert
// (Authority Information Access + CRL Distribution Points + OCSP).
// All optional; bao's `pki/config/urls` accepts an empty body.
type PKIURLs struct {
	// +kubebuilder:validation:Optional
	IssuingCertificates []string `json:"issuingCertificates,omitempty"`
	// +kubebuilder:validation:Optional
	CRLDistributionPoints []string `json:"crlDistributionPoints,omitempty"`
	// +kubebuilder:validation:Optional
	OCSPServers []string `json:"ocspServers,omitempty"`
}

// OpenBaoPKISecretEngineConfigSpec defines the desired state.
type OpenBaoPKISecretEngineConfigSpec struct {
	// Path is the bao-side PKI mount path (e.g. "pki", "pki/internal").
	// Must match an existing OpenBaoSecretEngine of kind=pki at the
	// same path; the controller does NOT enable the mount itself.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Path string `json:"path"`

	// OpenBaoNamespace targets a specific OpenBao namespace via
	// X-Vault-Namespace. Empty = root.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// PKIType selects the CA generation flavour. Only "root" is
	// supported. The enum is open-ended so other generation
	// flavours can be added additively without a CRD-shape break.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=root
	PKIType string `json:"pkiType"`

	// CommonName is the X.509 CN of the generated CA cert. Required.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	CommonName string `json:"commonName"`

	// TTL is the validity period of the CA cert as a bao duration
	// string (e.g. "87600h" for 10 years). Empty = bao default
	// (currently 30 days, deliberately short — set this for any
	// production CA).
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	TTL string `json:"ttl,omitempty"`

	// KeyType is the public-key algorithm. Defaults to bao's default
	// (rsa) when empty.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=rsa;ec;ed25519
	KeyType string `json:"keyType,omitempty"`

	// KeyBits is the key size in bits. RSA: 2048|3072|4096.
	// EC: 224|256|384|521. Ignored for ed25519. Zero = bao default.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=8192
	KeyBits int `json:"keyBits,omitempty"`

	// Subject groups the X.509 subject fields beyond CommonName.
	// +kubebuilder:validation:Optional
	Subject *PKISubject `json:"subject,omitempty"`

	// URLs configures the CA's published distribution points (AIA,
	// CRL, OCSP) embedded in every issued cert.
	// +kubebuilder:validation:Optional
	URLs *PKIURLs `json:"urls,omitempty"`
}

// OpenBaoPKISecretEngineConfigStatus defines the observed state.
type OpenBaoPKISecretEngineConfigStatus struct {
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// BaoWritten records whether this CR has ever successfully
	// generated a CA. Not used by the deletion path (IsDeletable=false
	// short-circuits BaoDelete unconditionally) but kept for status
	// observability.
	// +optional
	BaoWritten bool `json:"baoWritten,omitempty"`

	// LastWrittenBaoName records the PKI mount path the controller
	// last wrote a CA into. A spec.path change that produces a
	// different LastWrittenBaoName would leak a CA at the old mount
	// (because IsDeletable=false skips rename cleanup); the controller
	// logs this and advances the identity. Document and avoid renames
	// in production.
	// +optional
	LastWrittenBaoName string `json:"lastWrittenBaoName,omitempty"`

	// LastWrittenOpenBaoNamespace tracks the bao namespace context.
	// +optional
	LastWrittenOpenBaoNamespace string `json:"lastWrittenOpenBaoNamespace,omitempty"`

	// Phase tracks the CA-bootstrap state.
	// "" = no CA yet (just before first BaoWrite).
	// "Active" = CA generated and URLs published.
	// +optional
	Phase string `json:"phase,omitempty"`

	// CASerialNumber is the X.509 serial of the active CA cert,
	// captured from the bao response on initial generate. Surfaced
	// for operator visibility.
	// +optional
	CASerialNumber string `json:"caSerialNumber,omitempty"`
}

func (m *OpenBaoPKISecretEngineConfig) GetConditions() []metav1.Condition {
	return m.Status.Conditions
}

func (m *OpenBaoPKISecretEngineConfig) SetConditions(conditions []metav1.Condition) {
	m.Status.Conditions = conditions
}

func (m *OpenBaoPKISecretEngineConfig) IsBaoWritten() bool { return m.Status.BaoWritten }
func (m *OpenBaoPKISecretEngineConfig) MarkBaoWritten()    { m.Status.BaoWritten = true }

func (m *OpenBaoPKISecretEngineConfig) LastWrittenBaoName() string {
	return m.Status.LastWrittenBaoName
}

func (m *OpenBaoPKISecretEngineConfig) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}

func (m *OpenBaoPKISecretEngineConfig) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// MarkActive records the active CA's serial in status. Called by the
// controller after a successful root-CA generate.
func (m *OpenBaoPKISecretEngineConfig) MarkActive(serial string) {
	m.Status.Phase = PhaseActive
	m.Status.CASerialNumber = serial
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obpkic

// OpenBaoPKISecretEngineConfig is the Schema for the
// openbaopkisecretengineconfigs API.
type OpenBaoPKISecretEngineConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoPKISecretEngineConfigSpec   `json:"spec,omitempty"`
	Status OpenBaoPKISecretEngineConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoPKISecretEngineConfigList contains a list of
// OpenBaoPKISecretEngineConfig.
type OpenBaoPKISecretEngineConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoPKISecretEngineConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoPKISecretEngineConfig{}, &OpenBaoPKISecretEngineConfigList{})
}
