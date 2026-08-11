// OpenBaoAuthMethod owns the lifecycle of a bao auth-method mount at
// sys/auth/<path>. Sibling of OpenBaoSecretEngine — same enable /
// disable / tune shape, different bao endpoint. Auth mounts hold the
// bao-side authentication state for downstream primitives like
// OpenBaoCertAuthEngineConfig, OpenBaoJWTOIDCAuthEngineConfig, and
// the kubernetes auth mount used by OpenBaoKubernetesAuthRole. Every
// auth mount the operator manages — including type=kubernetes — is
// provisioned through this CR.
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

// AuthMethod type strings as bao expects them on the wire. Centralised
// so the validator and the controller's BaoWrite agree on the same
// spelling. Bao itself accepts more types than this list — extend as
// new ones are wired into downstream primitives.
const (
	AuthMethodTypeCert       = "cert"
	AuthMethodTypeJWT        = "jwt"
	AuthMethodTypeOIDC       = "oidc"
	AuthMethodTypeKubernetes = "kubernetes"
	AuthMethodTypeApprole    = "approle"
	AuthMethodTypeUserpass   = "userpass"
	AuthMethodTypeLDAP       = "ldap"
)

var supportedAuthMethodTypes = map[string]struct{}{
	AuthMethodTypeCert:       {},
	AuthMethodTypeJWT:        {},
	AuthMethodTypeOIDC:       {},
	AuthMethodTypeKubernetes: {},
	AuthMethodTypeApprole:    {},
	AuthMethodTypeUserpass:   {},
	AuthMethodTypeLDAP:       {},
}

var _ vaultobject.VaultObject = &OpenBaoAuthMethod{}
var _ vaultobject.ConditionsAware = &OpenBaoAuthMethod{}
var _ vaultobject.WriteTracker = &OpenBaoAuthMethod{}
var _ vaultobject.RenameTracker = &OpenBaoAuthMethod{}

func (d *OpenBaoAuthMethod) BaoName() string {
	return strings.Trim(d.Spec.Path, "/")
}

func (d *OpenBaoAuthMethod) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

// BaoPath returns the bao-side mount path with the trailing slash
// bao uses internally on read responses. Used as the join key by
// the drift comparator.
func (d *OpenBaoAuthMethod) BaoPath() string {
	return strings.Trim(d.Spec.Path, "/") + "/"
}

// GetPath returns a synthetic identifier for collision messages and
// logs. Embeds the auth-method type so logs distinguish at a glance
// between, e.g., a cert auth mount and a jwt auth mount that happen
// to share a path.
func (d *OpenBaoAuthMethod) GetPath() string {
	return "sys/auth/" + strings.Trim(d.Spec.Path, "/") + " (" + d.Spec.Type + ")"
}

func (d *OpenBaoAuthMethod) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"description": d.Spec.Description,
	}
}

// IsEquivalentToDesiredState compares against the bao-side read shape.
// Type drift surfaces as ImmutableTypeDrift via the controller (bao
// rejects type changes in place). Description trims whitespace;
// tunable config compares fields the spec actually pins — empty
// desired field adopts bao's value to avoid a write storm on a CR
// that doesn't override bao defaults.
func (d *OpenBaoAuthMethod) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	cur, ok := payload["mount"].(*baoclient.AuthMethodMount)
	if !ok || cur == nil {
		return false
	}
	if d.Spec.Type != strings.TrimSpace(cur.Type) {
		return false
	}
	if strings.TrimSpace(d.Spec.Description) != strings.TrimSpace(cur.Description) {
		return false
	}
	if !configFieldEqual(d.Spec.Config.DefaultLeaseTTL, cur.Config.DefaultLeaseTTL) {
		return false
	}
	if !configFieldEqual(d.Spec.Config.MaxLeaseTTL, cur.Config.MaxLeaseTTL) {
		return false
	}
	if !configFieldEqual(d.Spec.Config.ListingVisibility, cur.Config.ListingVisibility) {
		return false
	}
	return true
}

// configFieldEqual treats empty desired as "adopt bao's value" so a
// CR that doesn't pin a tunable field doesn't trigger a write storm
// against bao's mount default.
func configFieldEqual(desired, current string) bool {
	if strings.TrimSpace(desired) == "" {
		return true
	}
	return strings.TrimSpace(desired) == strings.TrimSpace(current)
}

// ToBaoSpec materializes the bao-wire payload from the CR.
func (d *OpenBaoAuthMethod) ToBaoSpec() baoclient.AuthMethodMountSpec {
	return baoclient.AuthMethodMountSpec{
		Type:        d.Spec.Type,
		Description: d.Spec.Description,
		Config: baoclient.AuthMethodConfig{
			DefaultLeaseTTL:   d.Spec.Config.DefaultLeaseTTL,
			MaxLeaseTTL:       d.Spec.Config.MaxLeaseTTL,
			ListingVisibility: d.Spec.Config.ListingVisibility,
		},
	}
}

func (d *OpenBaoAuthMethod) IsInitialized() bool { return true }

func (d *OpenBaoAuthMethod) IsDeletable() bool {
	return d.Spec.DeletionPolicy.DeletesDataKind()
}

func (d *OpenBaoAuthMethod) PrepareInternalValues(ctx context.Context, object client.Object) error {
	return nil
}
func (d *OpenBaoAuthMethod) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

// IsValid catches spec-level invariants kubebuilder markers can't
// express compactly.
func (d *OpenBaoAuthMethod) IsValid() (bool, error) {
	if strings.TrimSpace(d.Spec.Path) == "" {
		return false, fmt.Errorf("spec.path must not be empty")
	}
	if strings.TrimSpace(d.Spec.Type) == "" {
		return false, fmt.Errorf("spec.type must not be empty")
	}
	if _, ok := supportedAuthMethodTypes[d.Spec.Type]; !ok {
		return false, fmt.Errorf("spec.type %q is not a supported auth-method type "+
			"(supported: %v)", d.Spec.Type, sortedKeys(supportedAuthMethodTypes))
	}
	return true, nil
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Stable order so error messages don't flap.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// OpenBaoAuthMethodConfig mirrors the subset of bao's MountConfigInput
// the operator surfaces today.
type OpenBaoAuthMethodConfig struct {
	// DefaultLeaseTTL is a bao duration string ("1h", "3600s").
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	DefaultLeaseTTL string `json:"defaultLeaseTtl,omitempty"`

	// MaxLeaseTTL is a bao duration string ("1h", "3600s").
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	MaxLeaseTTL string `json:"maxLeaseTtl,omitempty"`

	// ListingVisibility controls whether unauthenticated users can
	// see this mount in the bao UI listing. "" (default) or "hidden"
	// — bao only accepts these two values.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=unauth;hidden
	ListingVisibility string `json:"listingVisibility,omitempty"`
}

// OpenBaoAuthMethodSpec defines the desired state of OpenBaoAuthMethod.
type OpenBaoAuthMethodSpec struct {
	// DeletionPolicy controls what happens to the bao-side auth mount
	// when this CR is deleted or its bao identity changes. Retain
	// (the default) releases the CR without touching bao: the auth
	// mount is intentionally orphaned and logged, and re-applying an
	// identical CR adopts it. Delete disables the auth mount and the
	// login roles under it; no secret data lives there, so this is
	// disruptive but rebuildable from CRs.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=Retain
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// Path is the bao-side auth-mount path (e.g. "cert", "jwt",
	// "oidc"). Trailing slashes are accepted but stripped before the
	// bao API call.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Path string `json:"path"`

	// Type is the auth-method type as bao expects on the wire.
	// Mutable through CR re-creation only — bao does not allow type
	// to change in place.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=cert;jwt;oidc;kubernetes;approle;userpass;ldap
	Type string `json:"type"`

	// Description is the bao-side mount description. Free-form;
	// mirrored verbatim into bao's mount info.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=512
	Description string `json:"description,omitempty"`

	// OpenBaoNamespace targets a specific OpenBao namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// Config holds the tunable mount-config fields bao exposes on
	// the /tune endpoint.
	// +kubebuilder:validation:Optional
	Config OpenBaoAuthMethodConfig `json:"config,omitempty"`
}

// OpenBaoAuthMethodStatus defines the observed state.
type OpenBaoAuthMethodStatus struct {
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

	// MountAccessor is the bao-side accessor of this auth mount.
	// Auth-method aliases (OIDC sub, JWT subject, cert CN) and
	// identity-group aliases bind by `mount_accessor`, so surfacing
	// it on status lets downstream CRs (notably OpenBaoGroupAlias)
	// reference the accessor without a manual `bao auth list` step.
	// +optional
	MountAccessor string `json:"mountAccessor,omitempty"`
}

func (m *OpenBaoAuthMethod) GetConditions() []metav1.Condition  { return m.Status.Conditions }
func (m *OpenBaoAuthMethod) SetConditions(c []metav1.Condition) { m.Status.Conditions = c }
func (m *OpenBaoAuthMethod) IsBaoWritten() bool                 { return m.Status.BaoWritten }
func (m *OpenBaoAuthMethod) MarkBaoWritten()                    { m.Status.BaoWritten = true }
func (m *OpenBaoAuthMethod) LastWrittenBaoName() string         { return m.Status.LastWrittenBaoName }
func (m *OpenBaoAuthMethod) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}
func (m *OpenBaoAuthMethod) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obam
// +kubebuilder:printcolumn:name="DeletionPolicy",type=string,JSONPath=`.spec.deletionPolicy`

// OpenBaoAuthMethod is the Schema for the openbaoauthmethods API.
// Reconciles a CR to a bao-side auth-method mount at sys/auth/<path>.
type OpenBaoAuthMethod struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoAuthMethodSpec   `json:"spec,omitempty"`
	Status OpenBaoAuthMethodStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoAuthMethodList contains a list of OpenBaoAuthMethod.
type OpenBaoAuthMethodList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoAuthMethod `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoAuthMethod{}, &OpenBaoAuthMethodList{})
}
