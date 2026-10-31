// OpenBaoDatabaseEngineConfig owns a single database secret-engine
// connection config at <mount>/config/<name>. It pairs with the
// OpenBaoDatabaseRole CRD: the connection establishes how the operator
// reaches a database (plugin, connection URL template, pool settings,
// TLS), and roles create dynamic credentials scoped to it.
//
// The database secret-engine MOUNT is deployment-owned — the operator
// provisioning step enables it (type=database) and this CR only manages
// the config beneath it. The mount path is a generic "database" by default
// and is shared across deployments; each owning deployment co-locates its
// own OpenBaoDatabaseEngineConfig, and connection names (not the mount)
// distinguish entries.
//
// Credentials are referenced by spec.credentialsRef (a k8s Secret resolved
// by the controller on write) and are never stored on the CR or echoed to
// status.
package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	baoclient "github.com/stakater/openbao-config-operator/internal/client"
	"github.com/stakater/openbao-config-operator/internal/vaultobject"
)

var _ vaultobject.VaultObject = &OpenBaoDatabaseEngineConfig{}
var _ vaultobject.ConditionsAware = &OpenBaoDatabaseEngineConfig{}
var _ vaultobject.WriteTracker = &OpenBaoDatabaseEngineConfig{}
var _ vaultobject.RenameTracker = &OpenBaoDatabaseEngineConfig{}

// DefaultDatabaseMount is the default bao-side mount for the database
// secret engine.
const DefaultDatabaseMount = "database"

// Default keys within a credentialsRef Secret, and the default role
// credential type.
const (
	// DefaultCredentialsUsernameKey is the default Secret key for the
	// connection username.
	DefaultCredentialsUsernameKey = "username"
	// DefaultCredentialsPasswordKey is the default Secret key for the
	// connection password.
	DefaultCredentialsPasswordKey = "password"
	// DefaultDatabaseCredentialType is bao's default credential_type for
	// dynamic roles.
	DefaultDatabaseCredentialType = "password"
)

// BaoName returns the connection name as it appears in bao. spec.name
// takes precedence over metadata.name when set.
func (d *OpenBaoDatabaseEngineConfig) BaoName() string {
	raw := d.Spec.Name
	if raw == "" {
		raw = d.Name
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func (d *OpenBaoDatabaseEngineConfig) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

// GetPath returns a synthetic identifier for collision messages: the bao
// config path <mount>/config/<name>.
func (d *OpenBaoDatabaseEngineConfig) GetPath() string {
	return strings.Trim(d.Mount(), "/") + "/config/" + d.BaoName()
}

// Mount returns the bao-side database mount, defaulting to "database".
func (d *OpenBaoDatabaseEngineConfig) Mount() string {
	if strings.TrimSpace(d.Spec.Mount) == "" {
		return DefaultDatabaseMount
	}
	return d.Spec.Mount
}

// GetPayload is unused by the drift comparator (it works against the bao
// read directly). Kept to satisfy VaultObject.
func (d *OpenBaoDatabaseEngineConfig) GetPayload() map[string]interface{} {
	return nil
}

// IsEquivalentToDesiredState compares the bao read against the spec.
// The credential pair is intentionally excluded: bao does not echo the
// connection password, and a credentials rotation must not register as
// config drift. The connection URL is compared with its password userinfo
// masked so a rotation never forces a rewrite.
func (d *OpenBaoDatabaseEngineConfig) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	cur, ok := payload["config"].(*baoclient.DatabaseConnectionConfig)
	if !ok || cur == nil {
		return false
	}
	if cur.PluginName != strings.TrimSpace(d.Spec.PluginName) {
		return false
	}
	if baoclient.MaskConnectionURL(cur.ConnectionURL) != baoclient.MaskConnectionURL(d.Spec.ConnectionURL) {
		return false
	}
	if !sortedEqual(d.Spec.AllowedRoles, cur.AllowedRoles) {
		return false
	}
	if d.Spec.VerifyConnection != cur.VerifyConnection {
		return false
	}
	if d.Spec.MaxOpenConnections != cur.MaxOpenConnections {
		return false
	}
	if d.Spec.MaxIdleConnections != cur.MaxIdleConnections {
		return false
	}
	if strings.TrimSpace(d.Spec.MaxConnectionLifetime) != strings.TrimSpace(cur.MaxConnectionLifetime) {
		return false
	}
	if strings.TrimSpace(d.Spec.TLSServerName) != strings.TrimSpace(cur.TLSServerName) {
		return false
	}
	if d.Spec.TLSSkipVerify != cur.TLSSkipVerify {
		return false
	}
	if strings.TrimSpace(d.Spec.PasswordPolicy) != strings.TrimSpace(cur.PasswordPolicy) {
		return false
	}
	return true
}

func (d *OpenBaoDatabaseEngineConfig) IsInitialized() bool { return true }

func (d *OpenBaoDatabaseEngineConfig) IsDeletable() bool {
	return d.Spec.DeletionPolicy.DeletesDataKind()
}

// PrepareInternalValues validates the referenced credentials Secret exists
// so the CR reports a clear controller-side error before a bao write is
// attempted. The username/password are NOT resolved into status — the
// controller reads them again at BaoWrite time and injects them into the
// write body in memory only.
func (d *OpenBaoDatabaseEngineConfig) PrepareInternalValues(ctx context.Context, object client.Object) error {
	if d.Spec.CredentialsRef == nil || strings.TrimSpace(d.Spec.CredentialsRef.Name) == "" {
		return fmt.Errorf("spec.credentialsRef must reference a Secret holding the connection username/password")
	}
	//nolint:staticcheck // untyped context key matches upstream VCO contract
	cl, ok := ctx.Value("kubeClient").(client.Client)
	if !ok || cl == nil {
		return fmt.Errorf("kube client not available in reconcile context")
	}
	secNS := strings.TrimSpace(d.Spec.CredentialsRef.Namespace)
	if secNS == "" {
		secNS = d.Namespace
	}
	var sec corev1.Secret
	if err := cl.Get(ctx, types.NamespacedName{Namespace: secNS, Name: d.Spec.CredentialsRef.Name}, &sec); err != nil {
		return fmt.Errorf("loading credentials Secret %s/%s: %w",
			secNS, d.Spec.CredentialsRef.Name, err)
	}
	return nil
}

func (d *OpenBaoDatabaseEngineConfig) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

// IsValid validates spec-level invariants beyond the CRD schema markers.
func (d *OpenBaoDatabaseEngineConfig) IsValid() (bool, error) {
	if d.BaoName() == "" {
		return false, fmt.Errorf("spec.name (or metadata.name) must not be empty")
	}
	if strings.TrimSpace(d.Spec.PluginName) == "" {
		return false, fmt.Errorf("spec.pluginName must not be empty")
	}
	if strings.TrimSpace(d.Spec.ConnectionURL) == "" {
		return false, fmt.Errorf("spec.connectionUrl must not be empty")
	}
	if strings.TrimSpace(d.Spec.ConnectionURL) != "" && !strings.Contains(d.Spec.ConnectionURL, "{{username}}") {
		return false, fmt.Errorf("spec.connectionUrl must contain the {{username}} placeholder (credentials are injected from spec.credentialsRef)")
	}
	if d.Spec.CredentialsRef == nil || strings.TrimSpace(d.Spec.CredentialsRef.Name) == "" {
		return false, fmt.Errorf("spec.credentialsRef must reference a Secret holding the connection username/password")
	}
	return true, nil
}

// DatabaseCredentialsRef points at a k8s Secret holding the connection
// admin username and password. The controller reads them at write time and
// never persists them to the CR.
type DatabaseCredentialsRef struct {
	// Name of the Secret holding the credentials.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace of the Secret. Defaults to this CR's namespace.
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`

	// UsernameKey is the Secret key holding the username.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="username"
	UsernameKey string `json:"usernameKey,omitempty"`

	// PasswordKey is the Secret key holding the password.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="password"
	PasswordKey string `json:"passwordKey,omitempty"`
}

// OpenBaoDatabaseEngineConfigSpec defines the desired state.
type OpenBaoDatabaseEngineConfigSpec struct {
	// DeletionPolicy controls what happens to the bao-side connection when
	// this CR is deleted or its bao identity changes. Retain (the default)
	// releases the CR without touching bao — the connection survives as a
	// logged orphan; use it so churn can never drop a connection that live
	// roles depend on. Delete removes the connection.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=Retain
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// Mount is the bao-side database engine mount. Defaults to "database".
	// All connections share this single mount.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="database"
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Mount string `json:"mount,omitempty"`

	// Name is the bao-side connection name. Defaults to metadata.name.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name,omitempty"`

	// OpenBaoNamespace targets a bao namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// PluginName is the database plugin serving this connection, e.g.
	// "mysql-database-plugin" or "postgresql-database-plugin".
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	PluginName string `json:"pluginName"`

	// ConnectionURL is the plugin connection template. It must contain the
	// {{username}} and typically {{password}} placeholders; the controller
	// interpolates the credentials resolved from spec.credentialsRef.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	ConnectionURL string `json:"connectionUrl"`

	// CredentialsRef references the k8s Secret holding the connection admin
	// username/password. Never persisted to the CR.
	// +kubebuilder:validation:Required
	CredentialsRef *DatabaseCredentialsRef `json:"credentialsRef"`

	// AllowedRoles is the set of role names permitted on this connection
	// (server-enforced via allowed_roles).
	// +kubebuilder:validation:Optional
	AllowedRoles []string `json:"allowedRoles,omitempty"`

	// VerifyConnection pings the database on write.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=true
	VerifyConnection bool `json:"verifyConnection,omitempty"`

	// MaxOpenConnections caps the pool. 0 = plugin default.
	// +kubebuilder:validation:Optional
	MaxOpenConnections int `json:"maxOpenConnections,omitempty"`

	// MaxIdleConnections caps the idle pool. 0 = plugin default.
	// +kubebuilder:validation:Optional
	MaxIdleConnections int `json:"maxIdleConnections,omitempty"`

	// MaxConnectionLifetime is a bao duration for max reuse of a single
	// connection.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	MaxConnectionLifetime string `json:"maxConnectionLifetime,omitempty"`

	// TLSServerName overrides the TLS server-name validation hostname.
	// +kubebuilder:validation:Optional
	TLSServerName string `json:"tlsServerName,omitempty"`

	// TLSSkipVerify disables TLS verification for the connection.
	// +kubebuilder:validation:Optional
	TLSSkipVerify bool `json:"tlsSkipVerify,omitempty"`

	// PasswordPolicy names a password policy applied to generated
	// credential passwords.
	// +kubebuilder:validation:Optional
	PasswordPolicy string `json:"passwordPolicy,omitempty"`
}

// OpenBaoDatabaseEngineConfigStatus defines the observed state.
type OpenBaoDatabaseEngineConfigStatus struct {
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

	// LastWrittenMount captures the bao mount the config was last written
	// into so a simultaneous spec.mount + spec.name edit cleans up the
	// previous connection at its real bao location.
	// +optional
	LastWrittenMount string `json:"lastWrittenMount,omitempty"`
}

func (m *OpenBaoDatabaseEngineConfig) GetConditions() []metav1.Condition {
	return m.Status.Conditions
}

func (m *OpenBaoDatabaseEngineConfig) SetConditions(conditions []metav1.Condition) {
	m.Status.Conditions = conditions
}

func (m *OpenBaoDatabaseEngineConfig) IsBaoWritten() bool { return m.Status.BaoWritten }
func (m *OpenBaoDatabaseEngineConfig) MarkBaoWritten()    { m.Status.BaoWritten = true }

func (m *OpenBaoDatabaseEngineConfig) LastWrittenBaoName() string {
	return m.Status.LastWrittenBaoName
}

func (m *OpenBaoDatabaseEngineConfig) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}

func (m *OpenBaoDatabaseEngineConfig) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// ToConnectionConfig materializes a baoclient.DatabaseConnectionConfig from
// the CR (structural fields). Username/Password are left empty — the
// controller injects them from spec.credentialsRef at write time.
func (d *OpenBaoDatabaseEngineConfig) ToConnectionConfig() baoclient.DatabaseConnectionConfig {
	return baoclient.DatabaseConnectionConfig{
		PluginName:            strings.TrimSpace(d.Spec.PluginName),
		ConnectionURL:         d.Spec.ConnectionURL,
		AllowedRoles:          append([]string(nil), d.Spec.AllowedRoles...),
		VerifyConnection:      d.Spec.VerifyConnection,
		MaxOpenConnections:    d.Spec.MaxOpenConnections,
		MaxIdleConnections:    d.Spec.MaxIdleConnections,
		MaxConnectionLifetime: strings.TrimSpace(d.Spec.MaxConnectionLifetime),
		TLSServerName:         strings.TrimSpace(d.Spec.TLSServerName),
		TLSSkipVerify:         d.Spec.TLSSkipVerify,
		PasswordPolicy:        strings.TrimSpace(d.Spec.PasswordPolicy),
	}
}

// ResolvedCredentials reads the CredentialsRef Secret and returns the
// username/password pair. The controller calls this at write time so the
// credential material never lands in CR status. Empty key names use the
// documented defaults.
func (d *OpenBaoDatabaseEngineConfig) ResolvedCredentials(ctx context.Context, cl client.Client) (username, password string, err error) {
	if d.Spec.CredentialsRef == nil || strings.TrimSpace(d.Spec.CredentialsRef.Name) == "" {
		return "", "", fmt.Errorf("spec.credentialsRef must reference a Secret")
	}
	secNS := strings.TrimSpace(d.Spec.CredentialsRef.Namespace)
	if secNS == "" {
		secNS = d.Namespace
	}
	userKey := strings.TrimSpace(d.Spec.CredentialsRef.UsernameKey)
	if userKey == "" {
		userKey = DefaultCredentialsUsernameKey
	}
	passKey := strings.TrimSpace(d.Spec.CredentialsRef.PasswordKey)
	if passKey == "" {
		passKey = DefaultCredentialsPasswordKey
	}
	var sec corev1.Secret
	if err := cl.Get(ctx, types.NamespacedName{Namespace: secNS, Name: d.Spec.CredentialsRef.Name}, &sec); err != nil {
		return "", "", fmt.Errorf("loading credentials Secret %s/%s: %w", secNS, d.Spec.CredentialsRef.Name, err)
	}
	username = string(sec.Data[userKey])
	if username == "" {
		return "", "", fmt.Errorf("credentials Secret %s/%s has no non-empty key %q",
			secNS, d.Spec.CredentialsRef.Name, userKey)
	}
	password = string(sec.Data[passKey])
	return username, password, nil
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obdbcn
// +kubebuilder:printcolumn:name="Plugin",type=string,JSONPath=`.spec.pluginName`
// +kubebuilder:printcolumn:name="Mount",type=string,JSONPath=`.spec.mount`

// OpenBaoDatabaseEngineConfig is the Schema for the
// openbaodatabaseengineconfigs API.
type OpenBaoDatabaseEngineConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoDatabaseEngineConfigSpec   `json:"spec,omitempty"`
	Status OpenBaoDatabaseEngineConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoDatabaseEngineConfigList contains a list of
// OpenBaoDatabaseEngineConfig.
type OpenBaoDatabaseEngineConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoDatabaseEngineConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoDatabaseEngineConfig{}, &OpenBaoDatabaseEngineConfigList{})
}
