// Adapted from redhat-cop/vault-config-operator
//
//	api/v1alpha1/groupalias_types.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b
//	<https://github.com/redhat-cop/vault-config-operator>
//
// Licensed under the Apache License, Version 2.0
// <https://www.apache.org/licenses/LICENSE-2.0>.
//
// Modifications relative to upstream:
//   - Kind renamed GroupAlias → OpenBaoGroupAlias.
//   - spec.openbaoNamespace added (X-Vault-Namespace target);
//     spec.authentication and spec.connection removed.
//   - Bao keys aliases by id, not by (name, mount_accessor). Status
//     stamps the bao-side id on first create so subsequent reads /
//     updates / deletes target the correct alias even after a CR
//     re-create or rename.
//   - spec.canonicalGroupRef: a strongly-typed reference to an
//     OpenBaoGroup CR (k8s namespace + name). PrepareInternalValues
//     resolves it to the parent group's bao id via the OpenBaoGroup's
//     status.GroupID. spec.canonicalId remains as an escape hatch for
//     wiring a CR to a bao group that was created out of band.
//
// OpenBaoGroupAlias maps a (name, mount_accessor) tuple from an external
// auth method (OIDC, JWT, LDAP, …) into a parent type=external
// OpenBaoGroup. Bao writes at identity/group-alias; reads at
// identity/group-alias/id/<id>; deletes at identity/group-alias/id/<id>.
package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/internal/vaultobject"
)

var _ vaultobject.VaultObject = &OpenBaoGroupAlias{}
var _ vaultobject.ConditionsAware = &OpenBaoGroupAlias{}
var _ vaultobject.WriteTracker = &OpenBaoGroupAlias{}
var _ vaultobject.RenameTracker = &OpenBaoGroupAlias{}

// BaoName returns the alias name as bao stores it. Aliases live under
// a (name, mount_accessor) tuple — the same name on different mounts
// is a different alias. Spec.name takes precedence over metadata.name.
func (d *OpenBaoGroupAlias) BaoName() string {
	raw := d.Spec.Name
	if raw == "" {
		raw = d.Name
	}
	return strings.TrimSpace(raw)
}

func (d *OpenBaoGroupAlias) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

// MountAccessor returns the bao auth-mount accessor this alias maps
// from. Trimmed of whitespace; lookup in admission is the user's
// responsibility (`bao auth list -format=json`).
func (d *OpenBaoGroupAlias) MountAccessor() string {
	return strings.TrimSpace(d.Spec.MountAccessor)
}

// GetPath returns the bao-side path identifier for collision messages
// and logs. Aliases live at identity/group-alias/id/<id> — until the
// id is stamped on status, the path includes the (mount, name) tuple
// for diagnostic clarity.
func (d *OpenBaoGroupAlias) GetPath() string {
	if d.Status.AliasID != "" {
		return "identity/group-alias/id/" + d.Status.AliasID
	}
	return "identity/group-alias (mount=" + d.MountAccessor() + ", name=" + d.BaoName() + ")"
}

func (d *OpenBaoGroupAlias) GetPayload() map[string]interface{} {
	return nil
}

// IsEquivalentToDesiredState compares the bao read against the spec.
// CanonicalID can change on the spec side without renaming the alias,
// so it's part of the comparison; mount_accessor is immutable on bao's
// side (changing it requires alias re-create) and is tracked via the
// rename path, not drift.
func (d *OpenBaoGroupAlias) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	cur, ok := payload["alias"].(*baoclient.IdentityGroupAlias)
	if !ok || cur == nil {
		return false
	}
	if d.BaoName() != cur.Name {
		return false
	}
	if d.MountAccessor() != cur.MountAccessor {
		return false
	}
	if d.Status.ResolvedCanonicalID != cur.CanonicalID {
		return false
	}
	return true
}

func (d *OpenBaoGroupAlias) IsInitialized() bool { return true }

func (d *OpenBaoGroupAlias) IsDeletable() bool {
	return d.Spec.DeletionPolicy.DeletesGrantKind()
}

// PrepareInternalValues resolves spec.canonicalGroupRef to a bao group
// id by reading the referenced OpenBaoGroup's status.GroupID. Empty
// canonicalGroupRef + empty canonicalId means the user hasn't picked a
// parent yet — surface as ErrInternal so the controller requeues
// rather than writing an alias bound to nothing.
//
// The kube client travels through the reconcile context under the
// untyped "kubeClient" key (set by the shared base). Reading it back
// here keeps the VaultObject interface signature stable while still
// letting primitives query the apiserver during preparation.
func (d *OpenBaoGroupAlias) PrepareInternalValues(ctx context.Context, object client.Object) error {
	if d.Spec.CanonicalID != "" {
		d.Status.ResolvedCanonicalID = strings.TrimSpace(d.Spec.CanonicalID)
		return nil
	}
	if d.Spec.CanonicalGroupRef == nil {
		return fmt.Errorf("spec.canonicalGroupRef or spec.canonicalId must be set so the alias has a parent group")
	}
	//nolint:staticcheck // untyped context key matches upstream VCO contract
	cl, ok := ctx.Value("kubeClient").(client.Client)
	if !ok || cl == nil {
		return fmt.Errorf("kube client not available in reconcile context; cannot resolve canonicalGroupRef")
	}
	parentNS := strings.TrimSpace(d.Spec.CanonicalGroupRef.Namespace)
	if parentNS == "" {
		parentNS = d.Namespace
	}
	parentName := strings.TrimSpace(d.Spec.CanonicalGroupRef.Name)
	if parentName == "" {
		return fmt.Errorf("spec.canonicalGroupRef.name must not be empty")
	}
	var parent OpenBaoGroup
	if err := cl.Get(ctx, types.NamespacedName{Namespace: parentNS, Name: parentName}, &parent); err != nil {
		return fmt.Errorf("loading canonicalGroupRef %s/%s: %w", parentNS, parentName, err)
	}
	if parent.Status.GroupID == "" {
		return fmt.Errorf("parent OpenBaoGroup %s/%s has not yet been written to bao "+
			"(status.groupId is empty); requeue until it is reconciled",
			parentNS, parentName)
	}
	d.Status.ResolvedCanonicalID = parent.Status.GroupID
	return nil
}

func (d *OpenBaoGroupAlias) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

// IsValid catches spec-level invariants. Most of the heavy lifting is
// in PrepareInternalValues (parent-group resolution); this guards
// against shapes that bao would reject deeper into the call.
func (d *OpenBaoGroupAlias) IsValid() (bool, error) {
	if d.BaoName() == "" {
		return false, fmt.Errorf("spec.name (or metadata.name) must not be empty")
	}
	if d.MountAccessor() == "" {
		return false, fmt.Errorf("spec.mountAccessor must not be empty (look up with `bao auth list -format=json`)")
	}
	if d.Spec.CanonicalID == "" && d.Spec.CanonicalGroupRef == nil {
		return false, fmt.Errorf("exactly one of spec.canonicalId or spec.canonicalGroupRef must be set")
	}
	if d.Spec.CanonicalID != "" && d.Spec.CanonicalGroupRef != nil {
		return false, fmt.Errorf("only one of spec.canonicalId or spec.canonicalGroupRef may be set")
	}
	return true, nil
}

// ToBaoSpec materialises the bao-wire payload. Status.AliasID and
// Status.ResolvedCanonicalID carry the values stamped by previous
// reconciles / PrepareInternalValues.
func (d *OpenBaoGroupAlias) ToBaoSpec() baoclient.IdentityGroupAliasSpec {
	return baoclient.IdentityGroupAliasSpec{
		ID:            d.Status.AliasID,
		Name:          d.BaoName(),
		MountAccessor: d.MountAccessor(),
		CanonicalID:   d.Status.ResolvedCanonicalID,
	}
}

// OpenBaoGroupRef is a strongly-typed pointer at another OpenBaoGroup CR.
// Namespace defaults to the alias CR's k8s namespace when empty.
type OpenBaoGroupRef struct {
	// Name of the OpenBaoGroup CR to bind to.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace of the OpenBaoGroup CR. Defaults to the alias CR's
	// own namespace when empty.
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`
}

// OpenBaoGroupAliasSpec defines the desired state.
type OpenBaoGroupAliasSpec struct {
	// DeletionPolicy controls what happens to the bao-side object
	// when this CR is deleted or its bao identity changes. Delete
	// (the default) removes it, so deleting the CR revokes the access
	// it granted. Retain releases the CR without touching bao — the
	// grant survives as an intentional, logged orphan that no CR
	// tracks afterward; use only where rendering churn must never
	// drop live access.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// Name is the alias name as it appears in the auth method
	// (e.g. an OIDC subject claim, an LDAP CN, a JWT sub). Defaults
	// to metadata.name. Aliases are not normalised — bao stores the
	// value verbatim, so a CR claiming `Alice` must match the auth
	// method's `Alice`, not `alice`.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=512
	Name string `json:"name,omitempty"`

	// OpenBaoNamespace targets a specific OpenBao namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// MountAccessor is the bao-side accessor of the auth mount this
	// alias maps from. Look up with `bao auth list -format=json |
	// jq -r '.["<mount>/"].accessor'`. Bao keys aliases by
	// (name, mount_accessor); the same name on different mounts is
	// a different alias.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	MountAccessor string `json:"mountAccessor"`

	// CanonicalGroupRef points at an OpenBaoGroup CR whose
	// status.GroupID is the alias's parent. Mutually exclusive
	// with spec.canonicalId. Use this form when both objects are
	// managed by this operator — it is robust to bao group
	// re-creation (the OpenBaoGroup re-stamps a new id; the alias
	// picks it up on next reconcile).
	// +kubebuilder:validation:Optional
	CanonicalGroupRef *OpenBaoGroupRef `json:"canonicalGroupRef,omitempty"`

	// CanonicalID is the literal bao group id this alias binds to.
	// Mutually exclusive with spec.canonicalGroupRef. Use only when
	// the parent group is managed out of band (e.g. created by an
	// administrator with the bao CLI).
	// +kubebuilder:validation:Optional
	CanonicalID string `json:"canonicalId,omitempty"`
}

// OpenBaoGroupAliasStatus defines the observed state.
type OpenBaoGroupAliasStatus struct {
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

	// AliasID is the bao-side alias id stamped on first create. Bao
	// keys aliases by id; without this stamped on status, a subsequent
	// reconcile that lost spec.canonicalId or saw a renamed parent
	// would create a duplicate alias instead of updating the existing
	// one. Recovered via FindIdentityGroupAlias on backfill.
	// +optional
	AliasID string `json:"aliasId,omitempty"`

	// LastWrittenMountAccessor captures the mount accessor the alias
	// was last written under. mount_accessor is immutable on bao's
	// side, so a spec edit that flips it has to delete the old
	// alias before creating a new one. Stored on status so
	// BaoDeleteIdentity can target the previous identity correctly.
	// +optional
	LastWrittenMountAccessor string `json:"lastWrittenMountAccessor,omitempty"`

	// ResolvedCanonicalID is the parent group id PrepareInternalValues
	// computed (from spec.canonicalId or spec.canonicalGroupRef →
	// OpenBaoGroup.status.groupId). Surfaced for visibility +
	// drift comparison; not user-settable.
	// +optional
	ResolvedCanonicalID string `json:"resolvedCanonicalId,omitempty"`
}

func (m *OpenBaoGroupAlias) GetConditions() []metav1.Condition  { return m.Status.Conditions }
func (m *OpenBaoGroupAlias) SetConditions(c []metav1.Condition) { m.Status.Conditions = c }
func (m *OpenBaoGroupAlias) IsBaoWritten() bool                 { return m.Status.BaoWritten }
func (m *OpenBaoGroupAlias) MarkBaoWritten()                    { m.Status.BaoWritten = true }
func (m *OpenBaoGroupAlias) LastWrittenBaoName() string         { return m.Status.LastWrittenBaoName }
func (m *OpenBaoGroupAlias) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}
func (m *OpenBaoGroupAlias) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obga

// OpenBaoGroupAlias is the Schema for the openbaogroupaliases API.
type OpenBaoGroupAlias struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoGroupAliasSpec   `json:"spec,omitempty"`
	Status OpenBaoGroupAliasStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoGroupAliasList contains a list of OpenBaoGroupAlias.
type OpenBaoGroupAliasList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoGroupAlias `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoGroupAlias{}, &OpenBaoGroupAliasList{})
}
