// Adapted from redhat-cop/vault-config-operator
//
//	api/v1alpha1/secretenginemount_types.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b
//	<https://github.com/redhat-cop/vault-config-operator>
//
// Licensed under the Apache License, Version 2.0
// <https://www.apache.org/licenses/LICENSE-2.0>.
//
// Significant divergences from upstream:
//
//   - Discriminated-union spec. Upstream's SecretEngineMount is generic
//     across engine types (caller passes spec.type as a string). Our
//     spec.kvV2 / spec.transit / spec.pki slots constrain the controller
//     to engines we actually validate, and generate per-engine kubebuilder
//     schemas instead of a free-form options map. Upstream covers more
//     engines; we add them as separate stories.
//   - spec.openbaoNamespace added: routes the bao API call to a specific
//     OpenBao namespace via the X-Vault-Namespace header. Upstream models
//     this on spec.authentication.namespace; we hoisted it to spec
//     because spec.authentication is removed.
//   - status.baoWritten plus IsBaoWritten/MarkBaoWritten added: the
//     deletion path needs a durable signal to decide whether to call
//     BaoDelete, since condition history is transient (apiserver
//     compaction, etcd backup restore) and rolling back a Ready=True
//     to False after a successful write must not leak the bao mount.
//   - status.lastWrittenBaoName / status.lastWrittenOpenBaoNamespace
//     added: track the bao identity of the last successful write so
//     spec-level rename (path or openbao namespace change) tears down
//     the previous mount instead of leaving an orphan.
//   - Auth-method mounts are NOT covered by this CRD. Upstream's
//     SecretEngineMount targets sys/mounts only; we follow that.
//     Auth methods are managed by the OpenBaoAuthMethod CRD.
package v1alpha1

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stakater/openbao-config-operator/internal/vaultobject"
)

var _ vaultobject.VaultObject = &OpenBaoSecretEngine{}
var _ vaultobject.ConditionsAware = &OpenBaoSecretEngine{}
var _ vaultobject.WriteTracker = &OpenBaoSecretEngine{}
var _ vaultobject.RenameTracker = &OpenBaoSecretEngine{}

// Engine type strings as bao expects them on its API. Centralized here
// so the discriminator switch and the controller's BaoWrite agree on
// the exact spelling — a typo would surface as a server-side 4xx
// mid-reconcile rather than at compile time.
const (
	engineTypeKV      = "kv"
	engineTypeTransit = "transit"
	engineTypePKI     = "pki"
)

// EngineType returns the bao engine type string this CR's spec selects
// (e.g. "kv" with version=2 options, "transit", "pki"). Returns
// ("", false) when no slot is set — IsValid catches that.
func (d *OpenBaoSecretEngine) EngineType() (baoType string, ok bool) {
	switch {
	case d.Spec.KvV2 != nil:
		return engineTypeKV, true
	case d.Spec.Transit != nil:
		return engineTypeTransit, true
	case d.Spec.PKI != nil:
		return engineTypePKI, true
	}
	return "", false
}

// OpenBaoNamespace returns the bao namespace this CR's API calls target.
// Empty string means the root namespace, matching the X-Vault-Namespace
// header semantics: absent header = root, present header = scoped.
func (d *OpenBaoSecretEngine) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

// BaoPath returns the bao-side mount path with the trailing slash bao
// uses internally on read responses. Used as the join key by the drift
// comparator.
func (d *OpenBaoSecretEngine) BaoPath() string {
	return strings.Trim(d.Spec.Path, "/") + "/"
}

// BaoName returns the canonical mount path this CR writes to OpenBao —
// spec.path with leading/trailing slashes trimmed. Used by the shared
// base for rename detection: when LastWrittenBaoName differs from
// BaoName(), the controller tears down the previous mount before
// recording the new identity.
func (d *OpenBaoSecretEngine) BaoName() string {
	return strings.Trim(d.Spec.Path, "/")
}

// GetPath returns a synthetic path identifier for use in collision
// messages and logs. Embeds the engine type so logs distinguish at a
// glance between, e.g., a KV-v2 mount and a Transit mount that happen
// to share a path.
func (d *OpenBaoSecretEngine) GetPath() string {
	baoType, _ := d.EngineType()
	return "sys/mounts/" + strings.Trim(d.Spec.Path, "/") + " (" + baoType + ")"
}

// GetPayload returns the desired bao-side mount payload. Used by the
// shared base for drift detection.
func (d *OpenBaoSecretEngine) GetPayload() map[string]interface{} {
	out := map[string]interface{}{
		"description": d.Spec.Description,
	}
	if d.Spec.KvV2 != nil {
		// kv-v2's distinguishing option is options.version=2; the
		// in-band controller logic also writes the engine type "kv"
		// at write time. Drift comparator compares the options map
		// only — the type cannot change without unmount/remount.
		out["options"] = map[string]string{"version": "2"}
	}
	// Transit and PKI carry no options.
	return out
}

// IsEquivalentToDesiredState compares against the bao-side read shape.
// Bao always echoes the description (as empty string when unset) and
// the options map (always present, sometimes empty). The comparator
// trims whitespace on description and treats nil/empty options maps as
// equivalent to avoid spurious drift from server defaults.
func (d *OpenBaoSecretEngine) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	desired := d.GetPayload()
	if strings.TrimSpace(asStringPayload(desired["description"])) != strings.TrimSpace(asStringPayload(payload["description"])) {
		return false
	}
	desiredOpts := normalizeOptions(desired["options"])
	currentOpts := normalizeOptions(payload["options"])
	return reflect.DeepEqual(desiredOpts, currentOpts)
}

// asStringPayload coerces the payload's description value (which the
// SDK marshals as string but tests may inject as nil) to a string.
// Mirrors asString in bao_client.go but lives here to avoid an import
// cycle.
func asStringPayload(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// normalizeOptions returns a non-nil map with bao defaults filled in.
// kv-v2 always emits {"version": "2"} on read; comparing against a
// missing options key would surface as drift on every reconcile.
func normalizeOptions(v interface{}) map[string]string {
	out := map[string]string{}
	switch x := v.(type) {
	case nil:
		return out
	case map[string]string:
		for k, v := range x {
			out[k] = v
		}
	case map[string]interface{}:
		for k, v := range x {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
	}
	return out
}

func (d *OpenBaoSecretEngine) IsInitialized() bool {
	return true
}

func (d *OpenBaoSecretEngine) IsDeletable() bool {
	return d.Spec.DeletionPolicy.DeletesDataKind()
}

// PrepareInternalValues is a no-op for OpenBaoSecretEngine today —
// nothing in the spec needs cluster-side resolution. Kept on the type
// so it satisfies the VaultObject interface.
func (d *OpenBaoSecretEngine) PrepareInternalValues(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoSecretEngine) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

// IsValid runs spec-level validation that is too rich for kubebuilder
// markers. The XOR check (exactly one engine slot set) is enforced
// here in addition to the CRD-level XValidation rule because envtest
// CRDs and crfake clients can bypass admission, and the controller
// must never enter the BaoWrite path with an ambiguous spec.
func (d *OpenBaoSecretEngine) IsValid() (bool, error) {
	count := 0
	if d.Spec.KvV2 != nil {
		count++
	}
	if d.Spec.Transit != nil {
		count++
	}
	if d.Spec.PKI != nil {
		count++
	}
	if count == 0 {
		return false, fmt.Errorf("exactly one of spec.kvV2, spec.transit, spec.pki must be set")
	}
	if count > 1 {
		return false, fmt.Errorf("only one of spec.kvV2, spec.transit, spec.pki may be set")
	}
	if strings.TrimSpace(d.Spec.Path) == "" {
		return false, fmt.Errorf("spec.path must not be empty")
	}
	return true, nil
}

// KvV2Spec selects a KV-v2 secret mount. The canonical option is
// options.version="2"; the empty struct is sufficient to enable the
// mount with KV-v2 defaults.
type KvV2Spec struct {
}

// TransitSpec selects a transit secret mount. Empty struct enables
// the mount with transit defaults.
type TransitSpec struct {
}

// PKISpec selects a PKI secret mount. The PKI mount is the bao-side
// container for OpenBaoPKISecretEngineConfig and
// OpenBaoPKISecretEngineRole CRs that target this same mount path.
type PKISpec struct {
}

// OpenBaoSecretEngineSpec defines the desired state of
// OpenBaoSecretEngine. Exactly one of the engine-type slots must be
// set; IsValid + the CRD's XValidation rule enforce the XOR.
type OpenBaoSecretEngineSpec struct {
	// DeletionPolicy controls what happens to the bao-side mount when
	// this CR is deleted or its bao identity (spec.path /
	// spec.openbaoNamespace) changes. Retain (the default) releases
	// the CR without touching bao: the mount is intentionally orphaned
	// and logged, and re-applying an identical CR adopts it. Delete
	// disables the mount, which destroys everything stored under it —
	// KV secrets, transit keys, or a PKI CA and its private key.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=Retain
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// Path is the bao-side mount path (e.g. "secret", "transit",
	// "pki"). Trailing slashes are accepted but stripped before the
	// bao API call.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Path string `json:"path"`

	// Description is the bao-side mount description. Free-form;
	// mirrored verbatim into bao's options.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=512
	Description string `json:"description,omitempty"`

	// OpenBaoNamespace targets a specific OpenBao namespace for this
	// mount's API calls (sets the X-Vault-Namespace header). Empty
	// (the default) means the root namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// KvV2 selects a kv-v2 secret engine mount. Mutually exclusive
	// with the other engine slots.
	// +kubebuilder:validation:Optional
	KvV2 *KvV2Spec `json:"kvV2,omitempty"`

	// Transit selects a transit secret engine mount. Mutually
	// exclusive with the other engine slots.
	// +kubebuilder:validation:Optional
	Transit *TransitSpec `json:"transit,omitempty"`

	// PKI selects a PKI secret engine mount. Mutually exclusive with
	// the other engine slots. The PKI mount holds the CA configured
	// via OpenBaoPKISecretEngineConfig and the issuance roles defined
	// via OpenBaoPKISecretEngineRole.
	// +kubebuilder:validation:Optional
	PKI *PKISpec `json:"pki,omitempty"`
}

// OpenBaoSecretEngineStatus defines the observed state of OpenBaoSecretEngine.
type OpenBaoSecretEngineStatus struct {
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// BaoWritten records whether this CR has ever successfully written
	// to OpenBao. Once set true it is never cleared. The shared
	// reconciler uses it on the deletion path to decide whether to call
	// BaoDelete.
	// +optional
	BaoWritten bool `json:"baoWritten,omitempty"`

	// LastWrittenBaoName captures the mount path the controller last
	// successfully enabled. The next reconcile compares this against the
	// current BaoName(); a mismatch means the user renamed via
	// spec.path and the controller disables the previous mount before
	// recording the new identity.
	// +optional
	LastWrittenBaoName string `json:"lastWrittenBaoName,omitempty"`

	// LastWrittenOpenBaoNamespace captures the OpenBao namespace the
	// mount was last enabled in. Combined with LastWrittenBaoName forms
	// the full identity tuple so a rename across openbao namespaces also
	// cleans up correctly.
	// +optional
	LastWrittenOpenBaoNamespace string `json:"lastWrittenOpenBaoNamespace,omitempty"`
}

func (m *OpenBaoSecretEngine) GetConditions() []metav1.Condition {
	return m.Status.Conditions
}

func (m *OpenBaoSecretEngine) SetConditions(conditions []metav1.Condition) {
	m.Status.Conditions = conditions
}

func (m *OpenBaoSecretEngine) IsBaoWritten() bool { return m.Status.BaoWritten }
func (m *OpenBaoSecretEngine) MarkBaoWritten()    { m.Status.BaoWritten = true }

func (m *OpenBaoSecretEngine) LastWrittenBaoName() string {
	return m.Status.LastWrittenBaoName
}

func (m *OpenBaoSecretEngine) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}

func (m *OpenBaoSecretEngine) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obse
// +kubebuilder:printcolumn:name="DeletionPolicy",type=string,JSONPath=`.spec.deletionPolicy`
// +kubebuilder:validation:XValidation:rule="[has(self.spec.kvV2), has(self.spec.transit), has(self.spec.pki)].filter(x, x).size() == 1",message="exactly one of spec.kvV2, spec.transit, spec.pki must be set"

// OpenBaoSecretEngine is the Schema for the openbaosecretengines API.
// Reconciles a CR to a bao-side secret-engine mount at sys/mounts/<path>.
type OpenBaoSecretEngine struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoSecretEngineSpec   `json:"spec,omitempty"`
	Status OpenBaoSecretEngineStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoSecretEngineList contains a list of OpenBaoSecretEngine.
type OpenBaoSecretEngineList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoSecretEngine `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoSecretEngine{}, &OpenBaoSecretEngineList{})
}
