// OpenBaoNamespace owns the lifecycle of an OpenBao namespace at
// sys/namespaces/<name>. Unlike OpenBaoPolicy / OpenBaoKubernetesAuthRole /
// OpenBaoMount, this type has **no upstream VCO equivalent** — VCO
// references Vault namespaces (via spec.authentication.namespace) but
// does not manage their lifecycle, because Vault namespaces are an
// Enterprise-only feature in upstream Vault. OpenBao ships namespaces in
// the OSS distribution, so we own the create / read / delete cycle here.
package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stakater-ab/openbao-config-operator/internal/vaultobject"
)

// reservedBaoNamespaceNames are bao-internal names the OpenBao server
// itself rejects at create time. We mirror the rejection at admission so
// the user gets a CR-level Invalid condition rather than a delayed bao
// 4xx mid-reconcile. Source:
// https://openbao.org/docs/concepts/namespaces/ — "OpenBao itself
// reserves the following namespace names: ., .., root, sys, audit, auth,
// cubbyhole, identity."
var reservedBaoNamespaceNames = map[string]struct{}{
	".":         {},
	"..":        {},
	"root":      {},
	"sys":       {},
	"audit":     {},
	"auth":      {},
	"cubbyhole": {},
	"identity":  {},
}

var _ vaultobject.VaultObject = &OpenBaoNamespace{}
var _ vaultobject.ConditionsAware = &OpenBaoNamespace{}
var _ vaultobject.WriteTracker = &OpenBaoNamespace{}

// BaoName returns the bao-side namespace name (the local segment under
// the parent context). If spec.name is empty, metadata.name is used.
// Trim+lower to match bao's name normalization.
func (d *OpenBaoNamespace) BaoName() string {
	raw := d.Spec.Name
	if raw == "" {
		raw = d.Name
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

// OpenBaoNamespace returns the parent bao namespace this CR's create
// targets. Empty string means root parent. Nested namespaces (e.g.
// "acme/sub") are addressed by setting spec.openbaoNamespace="acme/" on
// the CR that creates "sub". Same convention as every other primitive
// in this package — uniformity of semantics across kinds.
func (d *OpenBaoNamespace) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

// GetPath returns the bao API path. Used by the shared base for
// collision messages and logs; the controller routes through the
// dedicated CreateNamespace / GetNamespace / DeleteNamespace wrapper
// methods rather than emitting this string directly.
func (d *OpenBaoNamespace) GetPath() string {
	return vaultobject.CleansePath("sys/namespaces/" + d.BaoName())
}

// GetPayload returns the desired state. Bao namespaces have no
// per-namespace mutable spec the operator manages — creating a
// namespace is the action. The non-empty "name" field gives the
// shared base a concrete map to compare against bao's read shape.
func (d *OpenBaoNamespace) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"name": d.BaoName(),
	}
}

// IsEquivalentToDesiredState compares the desired payload against the
// current bao-side payload. With no per-namespace mutable spec yet,
// existence parity (the namespace is present at the right path) is the
// only check; the reconciler's BaoGet returning ErrBaoNotFound vs a
// real read drives the create-vs-no-op decision. The comparator only
// needs to confirm the read shape echoes a non-empty name — bao's
// "the namespace exists" signal.
// IsEquivalentToDesiredState returns true unconditionally for bao
// namespaces: there is no per-namespace mutable spec the operator
// manages, so presence (BaoGet returning non-nil) is the only state
// to compare. Returning true here means a successful read short-
// circuits the BaoWrite path. Add real field comparisons here if
// future bao versions expose mutable namespace settings (custom
// metadata, locked state, etc.).
func (d *OpenBaoNamespace) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	return true
}

func (d *OpenBaoNamespace) IsInitialized() bool {
	return true
}

func (d *OpenBaoNamespace) IsDeletable() bool {
	return d.Spec.DeletionPolicy.DeletesDataKind()
}

// PrepareInternalValues is a no-op for OpenBaoNamespace today.
func (d *OpenBaoNamespace) PrepareInternalValues(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoNamespace) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

// IsValid runs spec-level validation that is too rich for kubebuilder
// markers. Reserved-name rejection lives here because OpenBao's
// reserved-name list is a small enum that is more readable as a Go
// switch than as a long anti-Pattern. Defense in depth on a bypassed
// admission (stale CRD, fake client) — bao would reject these too,
// but failing earlier with a stable user-facing reason is better than
// flapping the controller through a bao 4xx.
func (d *OpenBaoNamespace) IsValid() (bool, error) {
	name := d.BaoName()
	if name == "" {
		return false, fmt.Errorf("spec.name (or metadata.name) must not be empty")
	}
	if _, reserved := reservedBaoNamespaceNames[name]; reserved {
		return false, fmt.Errorf("namespace name %q is reserved by OpenBao — pick a different name", name)
	}
	if strings.Contains(name, "/") {
		// CRD design: spec.name is the LOCAL segment within the parent
		// (set via spec.openbaoNamespace). Slashes here would create an
		// implicit nested namespace, which bypasses the explicit
		// parent-context model. Reject so the user is forced to use the
		// parent-context flag.
		return false, fmt.Errorf("spec.name %q must not contain '/' — use spec.openbaoNamespace to set a parent context", name)
	}
	return true, nil
}

// OpenBaoNamespaceSpec defines the desired state of OpenBaoNamespace.
type OpenBaoNamespaceSpec struct {
	// DeletionPolicy controls what happens to the bao-side namespace
	// when this CR is deleted or renamed. Retain (the default)
	// releases the CR without touching bao: the namespace is
	// intentionally orphaned and logged, and re-applying an identical
	// CR adopts it. Delete removes the bao namespace — bao's delete
	// cascades through everything inside it (mounts, auth methods,
	// secrets, keys, child namespaces), unrecoverably.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=Retain
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// Name is the bao-side namespace name (the local segment under
	// spec.openbaoNamespace). Defaults to metadata.name when empty;
	// override when the bao name must differ from the k8s resource
	// name. Pattern is anchored — OpenAPI v3's `pattern` keyword does
	// substring match by default, so an unanchored regex would accept
	// "Bad_Name1" because the substring "a" matches.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name,omitempty"`

	// OpenBaoNamespace is the parent context this namespace lives
	// inside. Empty (the default) creates the namespace at the bao
	// root. To create a nested namespace `acme/sub`, set spec.name=sub
	// and spec.openbaoNamespace=acme/. The controller calls bao's
	// create endpoint with X-Vault-Namespace set to this value.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`
}

// OpenBaoNamespaceStatus defines the observed state.
type OpenBaoNamespaceStatus struct {
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// BaoWritten records whether this CR has ever successfully created
	// the bao-side namespace. The shared reconciler uses it on the
	// deletion path to decide whether to call BaoDelete.
	// +optional
	BaoWritten bool `json:"baoWritten,omitempty"`

	// LastWrittenBaoName captures the bao namespace name the controller
	// last successfully created. The next reconcile compares this against
	// the current BaoName(); a mismatch means the user renamed via
	// spec.name and the controller deletes the previous bao namespace
	// before recording the new identity. Bao rejects deletion of a
	// namespace that still contains children, so a rename of a populated
	// bao namespace surfaces as Ready=False until the user removes the
	// children — preferable to the silent orphan the previous behavior
	// produced.
	// +optional
	LastWrittenBaoName string `json:"lastWrittenBaoName,omitempty"`

	// LastWrittenOpenBaoNamespace captures the parent OpenBao namespace
	// the controller last wrote into. Combined with LastWrittenBaoName
	// forms the full bao identity tuple so a rename across openbao
	// namespaces also cleans up correctly.
	// +optional
	LastWrittenOpenBaoNamespace string `json:"lastWrittenOpenBaoNamespace,omitempty"`
}

func (m *OpenBaoNamespace) GetConditions() []metav1.Condition {
	return m.Status.Conditions
}

func (m *OpenBaoNamespace) SetConditions(conditions []metav1.Condition) {
	m.Status.Conditions = conditions
}

func (m *OpenBaoNamespace) IsBaoWritten() bool { return m.Status.BaoWritten }
func (m *OpenBaoNamespace) MarkBaoWritten()    { m.Status.BaoWritten = true }

func (m *OpenBaoNamespace) LastWrittenBaoName() string {
	return m.Status.LastWrittenBaoName
}

func (m *OpenBaoNamespace) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}

func (m *OpenBaoNamespace) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obns
// +kubebuilder:printcolumn:name="DeletionPolicy",type=string,JSONPath=`.spec.deletionPolicy`

// OpenBaoNamespace is the Schema for the openbaonamespaces API.
// Reconciles a CR to a bao-side namespace at sys/namespaces/<name>
// (relative to spec.openbaoNamespace, if set).
type OpenBaoNamespace struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoNamespaceSpec   `json:"spec,omitempty"`
	Status OpenBaoNamespaceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoNamespaceList contains a list of OpenBaoNamespace.
type OpenBaoNamespaceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoNamespace `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoNamespace{}, &OpenBaoNamespaceList{})
}
