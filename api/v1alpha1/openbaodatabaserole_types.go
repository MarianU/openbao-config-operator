// OpenBaoDatabaseRole owns a single static role at <mount>/roles/<name> in
// the database secret engine. A role targets a connection (spec.database)
// and defines how dynamic credentials are created/rotated/revoked for it.
// Pairs with OpenBaoDatabaseEngineConfig at the same spec.mount (the
// connection must exist before the role can mint credentials).
//
// DeletionPolicy defaults to Retain: a role may be actively consumed by a
// VSO dynamic-secret reader (rollout-restart on rotation), so the operator
// must never drop it implicitly. Only an explicit Delete removes it.
package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/internal/vaultobject"
)

var _ vaultobject.VaultObject = &OpenBaoDatabaseRole{}
var _ vaultobject.ConditionsAware = &OpenBaoDatabaseRole{}
var _ vaultobject.WriteTracker = &OpenBaoDatabaseRole{}
var _ vaultobject.RenameTracker = &OpenBaoDatabaseRole{}

// BaoName returns the role name. spec.name takes precedence over
// metadata.name when set.
func (d *OpenBaoDatabaseRole) BaoName() string {
	raw := d.Spec.Name
	if raw == "" {
		raw = d.Name
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func (d *OpenBaoDatabaseRole) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

// GetPath returns a synthetic identifier for collision messages: the bao
// role path <mount>/roles/<name>.
func (d *OpenBaoDatabaseRole) GetPath() string {
	return strings.Trim(d.Mount(), "/") + "/roles/" + d.BaoName()
}

// Mount returns the bao-side database mount, defaulting to "database".
func (d *OpenBaoDatabaseRole) Mount() string {
	if strings.TrimSpace(d.Spec.Mount) == "" {
		return DefaultDatabaseMount
	}
	return d.Spec.Mount
}

// GetPayload is unused by the drift comparator. Kept to satisfy VaultObject.
func (d *OpenBaoDatabaseRole) GetPayload() map[string]interface{} {
	return nil
}

// IsEquivalentToDesiredState compares the bao read against the spec. The
// SQL statement lists are compared in order (statement sequencing matters —
// e.g. CREATE USER then GRANT) so no sorting is applied.
func (d *OpenBaoDatabaseRole) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	cur, ok := payload["role"].(*baoclient.DatabaseRoleSpec)
	if !ok || cur == nil {
		return false
	}
	if cur.Database != strings.TrimSpace(d.Spec.Database) {
		return false
	}
	if !equalStrings(d.Spec.CreationStatements, cur.CreationStatements) {
		return false
	}
	if !equalStrings(d.Spec.RotationStatements, cur.RotationStatements) {
		return false
	}
	if !equalStrings(d.Spec.RevocationStatements, cur.RevocationStatements) {
		return false
	}
	if !equalStrings(d.Spec.RollbackStatements, cur.RollbackStatements) {
		return false
	}
	curCredType := strings.TrimSpace(cur.CredentialType)
	specCredType := strings.TrimSpace(d.Spec.CredentialType)
	if specCredType == "" {
		// Bao default is "password".
		if curCredType != "" && curCredType != DefaultDatabaseCredentialType {
			return false
		}
	} else if specCredType != curCredType {
		return false
	}
	if strings.TrimSpace(d.Spec.DefaultTTL) != strings.TrimSpace(cur.DefaultTTL) {
		return false
	}
	if strings.TrimSpace(d.Spec.MaxTTL) != strings.TrimSpace(cur.MaxTTL) {
		return false
	}
	return true
}

func (d *OpenBaoDatabaseRole) IsInitialized() bool { return true }

func (d *OpenBaoDatabaseRole) IsDeletable() bool {
	return d.Spec.DeletionPolicy.DeletesGrantKind()
}

func (d *OpenBaoDatabaseRole) PrepareInternalValues(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoDatabaseRole) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

// IsValid validates spec-level invariants beyond the CRD schema markers.
func (d *OpenBaoDatabaseRole) IsValid() (bool, error) {
	if d.BaoName() == "" {
		return false, fmt.Errorf("spec.name (or metadata.name) must not be empty")
	}
	if strings.TrimSpace(d.Spec.Database) == "" {
		return false, fmt.Errorf("spec.database must name a connection (db_name) on the same mount")
	}
	if len(d.Spec.CreationStatements) == 0 {
		return false, fmt.Errorf("spec.creationStatements must not be empty (at least a CREATE USER statement)")
	}
	return true, nil
}

// equalStrings reports slice equality preserving order. Slices that are
// both empty/nil are equal.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// OpenBaoDatabaseRoleSpec defines the desired state.
type OpenBaoDatabaseRoleSpec struct {
	// DeletionPolicy controls what happens to the bao-side role when this
	// CR is deleted or its bao identity changes. Retain (the default)
	// releases the CR without touching bao — the role survives as a logged
	// orphan; required when a VSO dynamic-secret reader consumes the role.
	// Delete removes the role, stopping further credential minting through
	// it (existing creds keep their lease until they expire).
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=Retain
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// Mount is the bao-side database engine mount. Defaults to "database".
	// Must match the OpenBaoDatabaseEngineConfig holding the connection
	// named by spec.database.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="database"
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Mount string `json:"mount,omitempty"`

	// Name is the bao-side role name. Defaults to metadata.name.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name,omitempty"`

	// OpenBaoNamespace targets a bao namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// Database is the connection name (db_name) this role targets. The
	// OpenBaoDatabaseEngineConfig with that name must exist on spec.mount.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Database string `json:"database"`

	// CreationStatements are the SQL statements run on credential create
	// (e.g. CREATE USER followed by GRANT). Requires spec.database.
	// +kubebuilder:validation:Required
	CreationStatements []string `json:"creationStatements"`

	// RotationStatements are the SQL statements run on credential rotation.
	// +kubebuilder:validation:Optional
	RotationStatements []string `json:"rotationStatements,omitempty"`

	// RevocationStatements are the SQL statements run on lease revoke
	// (e.g. DROP USER).
	// +kubebuilder:validation:Optional
	RevocationStatements []string `json:"revocationStatements,omitempty"`

	// RollbackStatements clean up a partially-applied creation.
	// +kubebuilder:validation:Optional
	RollbackStatements []string `json:"rollbackStatements,omitempty"`

	// CredentialType for these plugins is "password".
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="password"
	CredentialType string `json:"credentialType,omitempty"`

	// DefaultTTL is the lease TTL of minted credentials (bao duration).
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	DefaultTTL string `json:"defaultTtl,omitempty"`

	// MaxTTL is the upper bound on minted credential TTL.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	MaxTTL string `json:"maxTtl,omitempty"`
}

// OpenBaoDatabaseRoleStatus defines the observed state.
type OpenBaoDatabaseRoleStatus struct {
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

	// LastWrittenMount captures the bao mount the role was last written into
	// so a simultaneous spec.mount + spec.name edit cleans up the previous
	// role at its real bao location.
	// +optional
	LastWrittenMount string `json:"lastWrittenMount,omitempty"`
}

func (m *OpenBaoDatabaseRole) GetConditions() []metav1.Condition {
	return m.Status.Conditions
}

func (m *OpenBaoDatabaseRole) SetConditions(conditions []metav1.Condition) {
	m.Status.Conditions = conditions
}

func (m *OpenBaoDatabaseRole) IsBaoWritten() bool { return m.Status.BaoWritten }
func (m *OpenBaoDatabaseRole) MarkBaoWritten()    { m.Status.BaoWritten = true }

func (m *OpenBaoDatabaseRole) LastWrittenBaoName() string {
	return m.Status.LastWrittenBaoName
}

func (m *OpenBaoDatabaseRole) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}

func (m *OpenBaoDatabaseRole) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// ToBaoSpec materializes a baoclient.DatabaseRoleSpec from the CR.
func (d *OpenBaoDatabaseRole) ToBaoSpec() baoclient.DatabaseRoleSpec {
	return baoclient.DatabaseRoleSpec{
		Database:             strings.TrimSpace(d.Spec.Database),
		CreationStatements:   append([]string(nil), d.Spec.CreationStatements...),
		RotationStatements:   append([]string(nil), d.Spec.RotationStatements...),
		RevocationStatements: append([]string(nil), d.Spec.RevocationStatements...),
		RollbackStatements:   append([]string(nil), d.Spec.RollbackStatements...),
		CredentialType:       d.Spec.CredentialType,
		DefaultTTL:           strings.TrimSpace(d.Spec.DefaultTTL),
		MaxTTL:               strings.TrimSpace(d.Spec.MaxTTL),
	}
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obdbr
// +kubebuilder:printcolumn:name="Database",type=string,JSONPath=`.spec.database`

// OpenBaoDatabaseRole is the Schema for the openbaodatabaseroles API.
type OpenBaoDatabaseRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoDatabaseRoleSpec   `json:"spec,omitempty"`
	Status OpenBaoDatabaseRoleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoDatabaseRoleList contains a list of OpenBaoDatabaseRole.
type OpenBaoDatabaseRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoDatabaseRole `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoDatabaseRole{}, &OpenBaoDatabaseRoleList{})
}
