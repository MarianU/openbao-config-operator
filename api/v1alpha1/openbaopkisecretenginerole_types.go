// Adapted from redhat-cop/vault-config-operator
//
//	api/v1alpha1/pkisecretenginerole_types.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b
//	<https://github.com/redhat-cop/vault-config-operator>
//
// Licensed under the Apache License, Version 2.0
// <https://www.apache.org/licenses/LICENSE-2.0>.
//
// Modifications relative to upstream:
//   - Kind renamed PKISecretEngineRole → OpenBaoPKISecretEngineRole.
//   - spec.openbaoNamespace added (X-Vault-Namespace target);
//     spec.authentication and spec.connection removed (operator uses
//     a single token from OpenBaoExtension).
//   - IsValid rejects roles that allow nothing — at least one of
//     allowAnyName, allowedDomains, allowGlobDomains, allowBareDomains,
//     allowSubdomains must be set or bao silently rejects every
//     issuance.
//   - IsEquivalentToDesiredState sorts list-shaped fields
//     (allowedDomains, keyUsage, extKeyUsage) before compare and
//     treats unset spec fields as bao defaults so a CR omitting
//     keyBits/serverFlag/clientFlag/etc. doesn't false-positive
//     against bao's defaults and trigger a write storm. TTL fields
//     are normalized to <n>s format on read for stable round-trip
//     with bao's int-seconds response.
//   - status.lastWrittenBaoName / status.lastWrittenOpenBaoNamespace
//     track the last-written identity for rename detection.
//     status.lastWrittenPath captures the bao mount path so a
//     simultaneous spec.name + spec.path edit cleans the previous
//     role at its real bao location.
//
// OpenBaoPKISecretEngineRole owns a single role at <mount>/roles/<name>.
// A role gates which certs may be issued from a PKI mount and what
// shape they take (allowed domains, key type/bits, TTL, EKU flags).
// Pairs with an OpenBaoPKISecretEngineConfig at the same spec.path
// (the PKI mount must have a CA before roles can issue from it).
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

var _ vaultobject.VaultObject = &OpenBaoPKISecretEngineRole{}
var _ vaultobject.ConditionsAware = &OpenBaoPKISecretEngineRole{}
var _ vaultobject.WriteTracker = &OpenBaoPKISecretEngineRole{}
var _ vaultobject.RenameTracker = &OpenBaoPKISecretEngineRole{}

// BaoName returns the role name as it appears in bao. spec.name takes
// precedence over metadata.name when set.
func (d *OpenBaoPKISecretEngineRole) BaoName() string {
	raw := d.Spec.Name
	if raw == "" {
		raw = d.Name
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func (d *OpenBaoPKISecretEngineRole) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

// GetPath returns a synthetic identifier for collision messages. The
// real bao path is <mount>/roles/<name>; including the mount path
// keeps logs unambiguous when two roles in different mounts share a
// name.
func (d *OpenBaoPKISecretEngineRole) GetPath() string {
	return strings.Trim(d.Spec.Path, "/") + "/roles/" + d.BaoName()
}

// GetPayload is unused by the comparator; IsEquivalentToDesiredState
// works against the bao read shape directly.
func (d *OpenBaoPKISecretEngineRole) GetPayload() map[string]interface{} {
	return nil
}

// IsEquivalentToDesiredState compares the bao read against the spec.
// Slice fields are sorted before compare because bao stores them as
// sets (server-side ordering is not stable). Bao defaults that the
// spec leaves zero are treated as equivalent — without this, every
// reconcile would observe drift on `key_bits=2048` (bao's default)
// when the user set `keyBits=0`.
func (d *OpenBaoPKISecretEngineRole) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	current, ok := payload["role"].(*baoclient.PKIRoleSpec)
	if !ok || current == nil {
		return false
	}
	desired := d.toBaoSpec()

	// Apply bao defaults to the desired side so a zero-valued spec
	// field doesn't false-positive on a bao default.
	applyDefaults(&desired, current)

	// Sort all string slices on both sides.
	desiredCopy := desired
	currentCopy := *current
	sortRoleSlices(&desiredCopy)
	sortRoleSlices(&currentCopy)

	return reflect.DeepEqual(desiredCopy, currentCopy)
}

// applyDefaults treats unset fields on the desired side as "whatever
// bao chose" so a spec that doesn't pin a field doesn't appear as
// drift against bao's server-side default. Without this, a minimal
// spec like {allowedDomains, allowSubdomains} would observe drift on
// every reconcile because bao's read echoes server_flag=true,
// client_flag=true, enforce_hostnames=true, allow_ip_sans=true,
// require_cn=true, key_usage=[DigitalSignature,KeyEncipherment],
// key_type=rsa, key_bits=2048 — none of which the spec set.
//
// Boolean defaults are handled specially: bao's read tells us the
// effective server-side value (after bao defaulting), but Go's zero
// value is false — so we cannot distinguish "user pinned false" from
// "user did not set it" without *bool. We accept the ambiguity in the
// direction that minimizes write-storms: a spec false for one of the
// bao-defaults-true booleans means "use bao default". To pin false
// explicitly today, set the bool true on the spec, then rely on bao's
// behaviour. Migrating these to *bool is the only way to disambiguate.
func applyDefaults(desired *baoclient.PKIRoleSpec, current *baoclient.PKIRoleSpec) {
	// String / numeric fields: zero-value on spec = "use bao value".
	if desired.KeyType == "" {
		desired.KeyType = current.KeyType
	}
	if desired.KeyBits == 0 {
		desired.KeyBits = current.KeyBits
	}
	if desired.TTL == "" {
		desired.TTL = current.TTL
	}
	if desired.MaxTTL == "" {
		desired.MaxTTL = current.MaxTTL
	}

	// Bao-defaults-true booleans: when the spec leaves them false,
	// adopt bao's value so the comparator doesn't see drift on every
	// reconcile. This matches the bao docs' default of true for these
	// flags (PKI roles default to a server-and-client cert profile).
	if !desired.ServerFlag {
		desired.ServerFlag = current.ServerFlag
	}
	if !desired.ClientFlag {
		desired.ClientFlag = current.ClientFlag
	}
	if !desired.EnforceHostnames {
		desired.EnforceHostnames = current.EnforceHostnames
	}
	if !desired.AllowIPSANs {
		desired.AllowIPSANs = current.AllowIPSANs
	}
	if !desired.RequireCN {
		desired.RequireCN = current.RequireCN
	}

	// Empty key_usage on spec = bao's default
	// (["DigitalSignature","KeyEncipherment"]). Comparing against
	// nil would force a write on every reconcile.
	if len(desired.KeyUsage) == 0 {
		desired.KeyUsage = append([]string(nil), current.KeyUsage...)
	}
}

func sortRoleSlices(s *baoclient.PKIRoleSpec) {
	sort.Strings(s.AllowedDomains)
	sort.Strings(s.KeyUsage)
	sort.Strings(s.ExtKeyUsage)
}

// toBaoSpec materializes a PKIRoleSpec from the CR. Used both for the
// drift comparator and for the BaoWrite call.
func (d *OpenBaoPKISecretEngineRole) toBaoSpec() baoclient.PKIRoleSpec {
	s := baoclient.PKIRoleSpec{
		AllowedDomains:   append([]string(nil), d.Spec.AllowedDomains...),
		AllowSubdomains:  d.Spec.AllowSubdomains,
		AllowBareDomains: d.Spec.AllowBareDomains,
		AllowAnyName:     d.Spec.AllowAnyName,
		EnforceHostnames: d.Spec.EnforceHostnames,
		AllowIPSANs:      d.Spec.AllowIPSANs,
		AllowGlobDomains: d.Spec.AllowGlobDomains,
		ServerFlag:       d.Spec.ServerFlag,
		ClientFlag:       d.Spec.ClientFlag,
		CodeSigningFlag:  d.Spec.CodeSigningFlag,
		EmailProtection:  d.Spec.EmailProtection,
		KeyType:          d.Spec.KeyType,
		KeyBits:          d.Spec.KeyBits,
		KeyUsage:         append([]string(nil), d.Spec.KeyUsage...),
		ExtKeyUsage:      append([]string(nil), d.Spec.ExtKeyUsage...),
		TTL:              d.Spec.TTL,
		MaxTTL:           d.Spec.MaxTTL,
		GenerateLease:    d.Spec.GenerateLease,
		NoStore:          d.Spec.NoStore,
		RequireCN:        d.Spec.RequireCN,
	}
	return s
}

// ToBaoSpec is the exported alias used by the controller package.
func (d *OpenBaoPKISecretEngineRole) ToBaoSpec() baoclient.PKIRoleSpec {
	return d.toBaoSpec()
}

func (d *OpenBaoPKISecretEngineRole) IsInitialized() bool { return true }
func (d *OpenBaoPKISecretEngineRole) IsDeletable() bool   { return true }

func (d *OpenBaoPKISecretEngineRole) PrepareInternalValues(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoPKISecretEngineRole) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

// IsValid catches spec-level invariants that kubebuilder markers
// can't express compactly: mutually-exclusive flags, empty allowed
// domain list when allowAnyName is false, etc.
func (d *OpenBaoPKISecretEngineRole) IsValid() (bool, error) {
	if strings.TrimSpace(d.Spec.Path) == "" {
		return false, fmt.Errorf("spec.path must not be empty")
	}
	// allowAnyName=true makes allowedDomains meaningless but harmless.
	// allowAnyName=false with empty allowedDomains and no other allow*
	// flags means no certs can be issued — surface as Invalid so the
	// user notices before bao silently rejects every issuance.
	if !d.Spec.AllowAnyName &&
		len(d.Spec.AllowedDomains) == 0 &&
		!d.Spec.AllowGlobDomains &&
		!d.Spec.AllowBareDomains &&
		!d.Spec.AllowSubdomains {
		return false, fmt.Errorf(
			"spec must specify at least one of: allowAnyName=true, allowedDomains, allowGlobDomains, allowBareDomains, allowSubdomains")
	}
	return true, nil
}

// OpenBaoPKISecretEngineRoleSpec mirrors bao's PKI role API.
// Field-by-field semantics live in the OpenBao docs at
// /pki/api-docs/index.html#create-update-role.
type OpenBaoPKISecretEngineRoleSpec struct {
	// Path is the bao-side PKI mount (e.g. "pki", "pki/internal").
	// Must match an existing OpenBaoSecretEngine of kind=pki at the
	// same path; the mount must also have a CA configured (typically
	// via OpenBaoPKISecretEngineConfig) before issued certs work.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Path string `json:"path"`

	// Name is the bao-side role name. Defaults to metadata.name.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name,omitempty"`

	// OpenBaoNamespace targets a bao namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// AllowedDomains restricts the CN/SAN of issued certs.
	// +kubebuilder:validation:Optional
	AllowedDomains []string `json:"allowedDomains,omitempty"`

	// +kubebuilder:validation:Optional
	AllowSubdomains bool `json:"allowSubdomains,omitempty"`
	// +kubebuilder:validation:Optional
	AllowBareDomains bool `json:"allowBareDomains,omitempty"`
	// +kubebuilder:validation:Optional
	AllowAnyName bool `json:"allowAnyName,omitempty"`
	// +kubebuilder:validation:Optional
	EnforceHostnames bool `json:"enforceHostnames,omitempty"`
	// +kubebuilder:validation:Optional
	AllowIPSANs bool `json:"allowIpSans,omitempty"`
	// +kubebuilder:validation:Optional
	AllowGlobDomains bool `json:"allowGlobDomains,omitempty"`

	// ServerFlag / ClientFlag / CodeSigningFlag / EmailProtection
	// gate which extKeyUsage values bao will sign. Default is
	// server+client (matches bao's defaults when omitted).
	// +kubebuilder:validation:Optional
	ServerFlag bool `json:"serverFlag,omitempty"`
	// +kubebuilder:validation:Optional
	ClientFlag bool `json:"clientFlag,omitempty"`
	// +kubebuilder:validation:Optional
	CodeSigningFlag bool `json:"codeSigningFlag,omitempty"`
	// +kubebuilder:validation:Optional
	EmailProtection bool `json:"emailProtection,omitempty"`

	// KeyType: rsa | ec | ed25519 | any.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=rsa;ec;ed25519;any
	KeyType string `json:"keyType,omitempty"`

	// KeyBits: 2048|3072|4096 for RSA, 224|256|384|521 for EC.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=8192
	KeyBits int `json:"keyBits,omitempty"`

	// KeyUsage / ExtKeyUsage are X.509 strings (e.g. DigitalSignature,
	// KeyEncipherment, ServerAuth). Bao validates the values.
	// +kubebuilder:validation:Optional
	KeyUsage []string `json:"keyUsage,omitempty"`
	// +kubebuilder:validation:Optional
	ExtKeyUsage []string `json:"extKeyUsage,omitempty"`

	// TTL / MaxTTL are bao duration strings ("1h", "3600s").
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	TTL string `json:"ttl,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	MaxTTL string `json:"maxTtl,omitempty"`

	// +kubebuilder:validation:Optional
	GenerateLease bool `json:"generateLease,omitempty"`
	// +kubebuilder:validation:Optional
	NoStore bool `json:"noStore,omitempty"`
	// +kubebuilder:validation:Optional
	RequireCN bool `json:"requireCN,omitempty"`
}

// OpenBaoPKISecretEngineRoleStatus defines the observed state.
type OpenBaoPKISecretEngineRoleStatus struct {
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

	// LastWrittenPath captures the bao mount path the controller last
	// wrote a role into. Without this, a CR that simultaneously edits
	// spec.name AND spec.path would orphan the role at the OLD path —
	// the rename-cleanup BaoDeleteIdentity would target the NEW path
	// and silently 404. The controller reads this field on rename
	// cleanup so the previous role is removed at its real bao
	// location.
	// +optional
	LastWrittenPath string `json:"lastWrittenPath,omitempty"`
}

func (m *OpenBaoPKISecretEngineRole) GetConditions() []metav1.Condition {
	return m.Status.Conditions
}

func (m *OpenBaoPKISecretEngineRole) SetConditions(conditions []metav1.Condition) {
	m.Status.Conditions = conditions
}

func (m *OpenBaoPKISecretEngineRole) IsBaoWritten() bool { return m.Status.BaoWritten }
func (m *OpenBaoPKISecretEngineRole) MarkBaoWritten()    { m.Status.BaoWritten = true }

func (m *OpenBaoPKISecretEngineRole) LastWrittenBaoName() string {
	return m.Status.LastWrittenBaoName
}

func (m *OpenBaoPKISecretEngineRole) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}

func (m *OpenBaoPKISecretEngineRole) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obpkir

// OpenBaoPKISecretEngineRole is the Schema for the
// openbaopkisecretengineroles API.
type OpenBaoPKISecretEngineRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoPKISecretEngineRoleSpec   `json:"spec,omitempty"`
	Status OpenBaoPKISecretEngineRoleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoPKISecretEngineRoleList contains a list of
// OpenBaoPKISecretEngineRole.
type OpenBaoPKISecretEngineRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoPKISecretEngineRole `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoPKISecretEngineRole{}, &OpenBaoPKISecretEngineRoleList{})
}
