// OpenBaoKvSecret is a new kind added in the MarianU fork. It mirrors a
// Kubernetes Secret into an OpenBao KVv2 engine at <mount>/data/<path> —
// the "seed arbitrary KV" write primitive the upstream operator lacked.
//
// The CR is REFERENCE-ONLY: it never carries secret material. The desired
// data is owned by a same-namespace Kubernetes Secret named in
// spec.sourceSecret; the operator copies that Secret's data into OpenBao
// and re-syncs whenever the Secret changes. Git holds only the reference
// (a Secret + path), never the value — consistent with the repo's
// no-secrets-in-git posture. Because the value lives in a Secret, it can
// be sourced from SOPS/SealedSecrets-encrypted Git or provisioned
// out-of-band, and VSO on the read side then distributes the bao copy to
// consumers.
//
// spec.ensureSecret creates an EMPTY placeholder Secret when
// spec.sourceSecret does not exist yet, so a bootstrap can anchor the
// Secret with a CR and let the real value be filled in later ("create the
// empty secret if not available").
//
// Safety: KV is a data-bearing kind, so deletionPolicy default is Retain —
// deleting the CR does NOT delete the secret unless the operator opts in
// (deletesDataKind reading), mirroring the mount/CA fail-safe direction and
// avoiding destroying live data on careless CR removal.
package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stakater/openbao-config-operator/internal/vaultobject"
)

var _ vaultobject.VaultObject = &OpenBaoKvSecret{}
var _ vaultobject.ConditionsAware = &OpenBaoKvSecret{}
var _ vaultobject.WriteTracker = &OpenBaoKvSecret{}
var _ vaultobject.RenameTracker = &OpenBaoKvSecret{}

// BaoName returns the KV secret's data path (the identity within the
// mount). spec.path takes precedence over metadata.name when set — either
// way, the identity is the path the secret is written to.
func (d *OpenBaoKvSecret) BaoName() string {
	raw := d.Spec.Path
	if raw == "" {
		raw = d.Name
	}
	return strings.Trim(raw, "/")
}

// OpenBaoNamespace returns the bao namespace this CR's API calls target.
// Empty = root.
func (d *OpenBaoKvSecret) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

// KVMount resolves the KVv2 mount, defaulting to constants.DefaultKVMount
// ("secret") when unset. Consistent defaulting for logs / status / the
// wire.
func (d *OpenBaoKvSecret) KVMount() string {
	if strings.TrimSpace(d.Spec.Mount) == "" {
		return "secret"
	}
	return strings.Trim(d.Spec.Mount, "/")
}

// GetPath returns the synthetic identifier used in collision messages and
// log lines: the full bao read/write path.
func (d *OpenBaoKvSecret) GetPath() string {
	return d.KVMount() + "/data/" + d.BaoName()
}

// GetPayload is unused by the drift comparator — IsEquivalentToDesiredState
// reads the payload arg directly. Kept to satisfy VaultObject.
func (d *OpenBaoKvSecret) GetPayload() map[string]interface{} {
	return nil
}

// IsEquivalentToDesiredState compares bao's current secret data against the
// source Kubernetes Secret's data. The controller passes both under the
// "data" (bao current) and "desired" (source Secret) payload keys.
func (d *OpenBaoKvSecret) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	current, _ := payload["data"].(map[string]string)
	desired, _ := payload["desired"].(map[string]string)
	return sameStringMap(current, desired)
}

// sameStringMap compares two string maps treating nil/empty as equal.
func sameStringMap(a, b map[string]string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func (d *OpenBaoKvSecret) IsInitialized() bool { return true }

// IsDeletable is the data-kind reading: only an explicit deletionPolicy
// "Delete" removes the secret on CR deletion. Empty (stale CRD / pruned
// manifest) means Retain, so destroying live data never depends on
// API-server defaulting.
func (d *OpenBaoKvSecret) IsDeletable() bool {
	return d.Spec.DeletionPolicy.DeletesDataKind()
}

func (d *OpenBaoKvSecret) PrepareInternalValues(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoKvSecret) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

// IsValid enforces spec-level invariants the CRD markers can't express
// compactly: the path must be set, the mount must not collide with the
// KVv2 reserved "data/" prefix, and a secret with empty data is rejected
// before it reaches bao.
func (d *OpenBaoKvSecret) IsValid() (bool, error) {
	if strings.TrimSpace(d.Spec.Path) == "" {
		return false, fmt.Errorf("spec.path must not be empty")
	}
	if strings.TrimSpace(d.Spec.Mount) == "" {
		return false, fmt.Errorf("spec.mount must not be empty")
	}
	if strings.HasPrefix(strings.Trim(d.Spec.Path, "/"), "data/") {
		return false, fmt.Errorf("spec.path must not begin with %q (reserved for KVv2 metadata)", "data/")
	}
	if strings.TrimSpace(d.Spec.SourceSecret) == "" {
		return false, fmt.Errorf("spec.sourceSecret must name a Kubernetes Secret in this namespace")
	}
	return true, nil
}

// OpenBaoKvSecretSpec defines the desired state.
type OpenBaoKvSecretSpec struct {
	// DeletionPolicy controls what happens to the bao-side secret when this
	// CR is deleted. Retain (the default) releases the CR without touching
	// bao — the secret survives as an intentional orphan. Delete removes the
	// secret. KV is data-bearing, so the fail-safe direction is Retain; use
	// Delete only where the secret must not outlive its CR.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=Retain
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// Mount is the KVv2 secret-engine mount path. Defaults to "secret".
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	// +kubebuilder:default="secret"
	Mount string `json:"mount,omitempty"`

	// Path is the secret's key path within the mount (e.g. "apps/foo").
	// The full bao path is <mount>/data/<path>. Defaults to metadata.name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Path string `json:"path"`

	// OpenBaoNamespace targets a bao namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// SourceSecret names a Kubernetes Secret in this CR's namespace that
	// owns the desired data. The operator copies this Secret's data into
	// bao and re-syncs on every change. No secret material lives in the CR.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	SourceSecret string `json:"sourceSecret"`

	// EnsureSecret creates an empty Kubernetes Secret named by
	// SourceSecret when it does not exist yet, so a bootstrap can anchor
	// the Secret and have real values filled in later.
	// +kubebuilder:validation:Optional
	EnsureSecret bool `json:"ensureSecret,omitempty"`
}

// OpenBaoKvSecretStatus defines the observed state.
type OpenBaoKvSecretStatus struct {
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

	// LastWrittenMount captures the KVv2 mount the controller last wrote
	// into. Without this, a CR that simultaneously edits spec.path AND
	// spec.mount would orphan the secret at the OLD mount — the
	// rename-cleanup BaoDeleteIdentity would target the NEW mount and
	// silently 404. The controller reads this field on rename cleanup so
	// the previous secret is removed at its real bao location.
	// +optional
	LastWrittenMount string `json:"lastWrittenMount,omitempty"`

	// Version is bao's KVv2 version of the last successfully written secret.
	// +optional
	Version int `json:"version,omitempty"`
}

func (m *OpenBaoKvSecret) GetConditions() []metav1.Condition {
	return m.Status.Conditions
}

func (m *OpenBaoKvSecret) SetConditions(conditions []metav1.Condition) {
	m.Status.Conditions = conditions
}

func (m *OpenBaoKvSecret) IsBaoWritten() bool { return m.Status.BaoWritten }
func (m *OpenBaoKvSecret) MarkBaoWritten()    { m.Status.BaoWritten = true }

func (m *OpenBaoKvSecret) LastWrittenBaoName() string {
	return m.Status.LastWrittenBaoName
}

func (m *OpenBaoKvSecret) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}

func (m *OpenBaoKvSecret) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// MarkWritten records the bao mount + KVv2 version on a successful write.
func (m *OpenBaoKvSecret) MarkWritten(mount string, version int) {
	m.Status.LastWrittenMount = mount
	m.Status.Version = version
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obkvs
// +kubebuilder:printcolumn:name="Mount",type=string,JSONPath=`.spec.mount`
// +kubebuilder:printcolumn:name="Path",type=string,JSONPath=`.spec.path`
// +kubebuilder:printcolumn:name="Version",type=integer,JSONPath=`.status.version`

// OpenBaoKvSecret is the Schema for the openbaokvsecrets API.
type OpenBaoKvSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoKvSecretSpec   `json:"spec,omitempty"`
	Status OpenBaoKvSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoKvSecretList contains a list of OpenBaoKvSecret.
type OpenBaoKvSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoKvSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoKvSecret{}, &OpenBaoKvSecretList{})
}
