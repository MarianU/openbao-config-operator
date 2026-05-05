// Adapted from redhat-cop/vault-config-operator
//
//	api/v1alpha1/jwtoidcauthengineconfig_types.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b
//	<https://github.com/redhat-cop/vault-config-operator>
//
// Licensed under the Apache License, Version 2.0
// <https://www.apache.org/licenses/LICENSE-2.0>.
//
// Modifications relative to upstream:
//   - Kind renamed JWTOIDCAuthEngineConfig → OpenBaoJWTOIDCAuthEngineConfig.
//   - spec.openbaoNamespace added; spec.authentication / spec.connection
//     removed.
//   - oidcClientSecret comes from a Kubernetes Secret via
//     spec.oidcClientSecretRef. The cleartext value never appears in
//     the CR spec; PrepareInternalValues resolves it at reconcile time.
//   - Pairs with an OpenBaoAuthMethod of type=jwt or type=oidc at the
//     same path.
package v1alpha1

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject"
)

var _ vaultobject.VaultObject = &OpenBaoJWTOIDCAuthEngineConfig{}
var _ vaultobject.ConditionsAware = &OpenBaoJWTOIDCAuthEngineConfig{}
var _ vaultobject.WriteTracker = &OpenBaoJWTOIDCAuthEngineConfig{}
var _ vaultobject.RenameTracker = &OpenBaoJWTOIDCAuthEngineConfig{}

func (d *OpenBaoJWTOIDCAuthEngineConfig) BaoName() string {
	return strings.Trim(d.Spec.Path, "/")
}

func (d *OpenBaoJWTOIDCAuthEngineConfig) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

func (d *OpenBaoJWTOIDCAuthEngineConfig) GetPath() string {
	return "auth/" + strings.Trim(d.Spec.Path, "/") + "/config"
}

func (d *OpenBaoJWTOIDCAuthEngineConfig) GetPayload() map[string]interface{} {
	return nil
}

// IsEquivalentToDesiredState compares the spec against the bao read.
// String fields with empty desired adopt bao's value (no drift).
// Slices are sorted before compare. The OIDC client secret is
// compared via the resolved value (status.ResolvedClientSecret) to
// detect rotations of the underlying Secret.
func (d *OpenBaoJWTOIDCAuthEngineConfig) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	cur, ok := payload["config"].(*baoclient.JWTOIDCConfigSpec)
	if !ok || cur == nil {
		return false
	}
	if !stringEqualOrAdopt(d.Spec.OIDCDiscoveryURL, cur.OIDCDiscoveryURL) {
		return false
	}
	if !stringEqualOrAdopt(d.Spec.OIDCDiscoveryCAPEM, cur.OIDCDiscoveryCAPEM) {
		return false
	}
	if !stringEqualOrAdopt(d.Spec.OIDCClientID, cur.OIDCClientID) {
		return false
	}
	// Bao's read may redact / not return the client_secret; treat
	// the resolved value as the source of truth and compare only
	// when bao actually echoes a non-empty value.
	if d.Status.ResolvedClientSecret != "" && cur.OIDCClientSecret != "" &&
		d.Status.ResolvedClientSecret != cur.OIDCClientSecret {
		return false
	}
	if !stringEqualOrAdopt(d.Spec.OIDCResponseMode, cur.OIDCResponseMode) {
		return false
	}
	if !sortedSliceEqualOrEmpty(d.Spec.OIDCResponseTypes, cur.OIDCResponseTypes) {
		return false
	}
	if !stringEqualOrAdopt(d.Spec.JWKsURL, cur.JWKsURL) {
		return false
	}
	if !stringEqualOrAdopt(d.Spec.JWKsCAPEM, cur.JWKsCAPEM) {
		return false
	}
	if !sortedSliceEqualOrEmpty(d.Spec.JWTValidationPubkeys, cur.JWTValidationPubkeys) {
		return false
	}
	if !sortedSliceEqualOrEmpty(d.Spec.JWTSupportedAlgs, cur.JWTSupportedAlgs) {
		return false
	}
	if !stringEqualOrAdopt(d.Spec.BoundIssuer, cur.BoundIssuer) {
		return false
	}
	if !stringEqualOrAdopt(d.Spec.DefaultRole, cur.DefaultRole) {
		return false
	}
	return true
}

// stringEqualOrAdopt returns true when the desired field is empty
// (adopt bao's value) or when the trimmed values match.
func stringEqualOrAdopt(desired, current string) bool {
	if strings.TrimSpace(desired) == "" {
		return true
	}
	return strings.TrimSpace(desired) == strings.TrimSpace(current)
}

func sortedSliceEqualOrEmpty(desired, current []string) bool {
	if len(desired) == 0 {
		return true
	}
	a := append([]string(nil), desired...)
	b := append([]string(nil), current...)
	sort.Strings(a)
	sort.Strings(b)
	return reflect.DeepEqual(a, b)
}

func (d *OpenBaoJWTOIDCAuthEngineConfig) IsInitialized() bool { return true }

// IsDeletable returns false for the same reason as the cert auth
// config: bao's auth/<mount>/config has no DELETE endpoint. The CR
// finalizer releases without touching bao on CR delete.
func (d *OpenBaoJWTOIDCAuthEngineConfig) IsDeletable() bool { return false }

// PrepareInternalValues resolves spec.oidcClientSecretRef into the
// bao-wire client_secret. Empty ref leaves status.ResolvedClientSecret
// unset; the spec just doesn't carry a client secret on the wire.
func (d *OpenBaoJWTOIDCAuthEngineConfig) PrepareInternalValues(ctx context.Context, object client.Object) error {
	if d.Spec.OIDCClientSecretRef == nil {
		d.Status.ResolvedClientSecret = ""
		return nil
	}
	//nolint:staticcheck // matches the shared base contract
	cl, ok := ctx.Value("kubeClient").(client.Client)
	if !ok || cl == nil {
		return fmt.Errorf("kube client not available in reconcile context")
	}
	secNS := strings.TrimSpace(d.Spec.OIDCClientSecretRef.Namespace)
	if secNS == "" {
		secNS = d.Namespace
	}
	secName := strings.TrimSpace(d.Spec.OIDCClientSecretRef.Name)
	if secName == "" {
		return fmt.Errorf("spec.oidcClientSecretRef.name must not be empty")
	}
	key := d.Spec.OIDCClientSecretRef.Key
	if key == "" {
		key = "oidcClientSecret"
	}
	var sec corev1.Secret
	if err := cl.Get(ctx, types.NamespacedName{Namespace: secNS, Name: secName}, &sec); err != nil {
		return fmt.Errorf("loading OIDC client secret %s/%s: %w", secNS, secName, err)
	}
	body, ok := sec.Data[key]
	if !ok || len(body) == 0 {
		return fmt.Errorf("Secret %s/%s key %q is empty or missing", secNS, secName, key)
	}
	d.Status.ResolvedClientSecret = string(body)
	return nil
}

func (d *OpenBaoJWTOIDCAuthEngineConfig) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoJWTOIDCAuthEngineConfig) IsValid() (bool, error) {
	if strings.TrimSpace(d.Spec.Path) == "" {
		return false, fmt.Errorf("spec.path must name a jwt or oidc auth mount")
	}
	// At least one of OIDCDiscoveryURL, JWKsURL, or JWTValidationPubkeys
	// must be set — bao rejects a config that gives it no way to validate
	// inbound tokens.
	hasOIDC := strings.TrimSpace(d.Spec.OIDCDiscoveryURL) != ""
	hasJWKS := strings.TrimSpace(d.Spec.JWKsURL) != ""
	hasPubkeys := len(d.Spec.JWTValidationPubkeys) > 0
	if !hasOIDC && !hasJWKS && !hasPubkeys {
		return false, fmt.Errorf("one of spec.oidcDiscoveryUrl, spec.jwksUrl, or spec.jwtValidationPubkeys must be set " +
			"(bao needs a way to validate inbound tokens)")
	}
	return true, nil
}

func (d *OpenBaoJWTOIDCAuthEngineConfig) ToBaoSpec() baoclient.JWTOIDCConfigSpec {
	return baoclient.JWTOIDCConfigSpec{
		OIDCDiscoveryURL:     d.Spec.OIDCDiscoveryURL,
		OIDCDiscoveryCAPEM:   d.Spec.OIDCDiscoveryCAPEM,
		OIDCClientID:         d.Spec.OIDCClientID,
		OIDCClientSecret:     d.Status.ResolvedClientSecret,
		OIDCResponseMode:     d.Spec.OIDCResponseMode,
		OIDCResponseTypes:    append([]string(nil), d.Spec.OIDCResponseTypes...),
		JWKsURL:              d.Spec.JWKsURL,
		JWKsCAPEM:            d.Spec.JWKsCAPEM,
		JWTValidationPubkeys: append([]string(nil), d.Spec.JWTValidationPubkeys...),
		JWTSupportedAlgs:     append([]string(nil), d.Spec.JWTSupportedAlgs...),
		BoundIssuer:          d.Spec.BoundIssuer,
		DefaultRole:          d.Spec.DefaultRole,
	}
}

// OIDCClientSecretRef points at a Kubernetes Secret holding the
// OIDC client_secret. The Secret is read on every reconcile; a
// rotation re-enqueues the CR via the Secret watch.
type OIDCClientSecretRef struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`

	// +kubebuilder:validation:Optional
	Key string `json:"key,omitempty"`
}

// OpenBaoJWTOIDCAuthEngineConfigSpec defines the desired state.
type OpenBaoJWTOIDCAuthEngineConfigSpec struct {
	// Path is the bao-side jwt or oidc auth mount path. Pairs with an
	// OpenBaoAuthMethod of type=jwt or type=oidc at the same path.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Path string `json:"path"`

	// OpenBaoNamespace targets a specific OpenBao namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// OIDCDiscoveryURL is the OIDC provider's well-known discovery
	// endpoint. Mutually exclusive with jwksUrl /
	// jwtValidationPubkeys; bao validates inbound tokens against
	// the keys this URL advertises.
	// +kubebuilder:validation:Optional
	OIDCDiscoveryURL string `json:"oidcDiscoveryUrl,omitempty"`

	// OIDCDiscoveryCAPEM is the optional PEM-encoded CA bundle used
	// to verify the discovery URL's TLS cert.
	// +kubebuilder:validation:Optional
	OIDCDiscoveryCAPEM string `json:"oidcDiscoveryCaPem,omitempty"`

	// OIDCClientID is the OAuth2 client id bao presents to the
	// provider.
	// +kubebuilder:validation:Optional
	OIDCClientID string `json:"oidcClientId,omitempty"`

	// OIDCClientSecretRef points at a Kubernetes Secret holding the
	// OAuth2 client_secret. The cleartext value never lands in the
	// CR spec.
	// +kubebuilder:validation:Optional
	OIDCClientSecretRef *OIDCClientSecretRef `json:"oidcClientSecretRef,omitempty"`

	// OIDCResponseMode is bao's "response_mode" param to the OIDC
	// provider on login.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=query;form_post
	OIDCResponseMode string `json:"oidcResponseMode,omitempty"`

	// OIDCResponseTypes is bao's "response_type" list. Typical
	// values are "code" or "id_token".
	// +kubebuilder:validation:Optional
	OIDCResponseTypes []string `json:"oidcResponseTypes,omitempty"`

	// JWKsURL is a static JWKS endpoint bao polls for token-signing
	// keys. Mutually exclusive with oidcDiscoveryUrl in the typical
	// OIDC case; for plain JWT auth, JWKsURL is the primary key
	// source.
	// +kubebuilder:validation:Optional
	JWKsURL string `json:"jwksUrl,omitempty"`

	// JWKsCAPEM is the optional PEM-encoded CA bundle used to verify
	// the JWKS URL's TLS cert.
	// +kubebuilder:validation:Optional
	JWKsCAPEM string `json:"jwksCaPem,omitempty"`

	// JWTValidationPubkeys is the list of static PEM-encoded public
	// keys bao validates inbound tokens against. Mutually exclusive
	// with oidcDiscoveryUrl + jwksUrl.
	// +kubebuilder:validation:Optional
	JWTValidationPubkeys []string `json:"jwtValidationPubkeys,omitempty"`

	// JWTSupportedAlgs restricts which JWT signing algorithms bao
	// will accept (e.g. RS256, ES256).
	// +kubebuilder:validation:Optional
	JWTSupportedAlgs []string `json:"jwtSupportedAlgs,omitempty"`

	// BoundIssuer narrows accepted tokens to those whose "iss" claim
	// matches.
	// +kubebuilder:validation:Optional
	BoundIssuer string `json:"boundIssuer,omitempty"`

	// DefaultRole names the role bao falls back to when the inbound
	// login does not pick one. Must reference an
	// OpenBaoJWTOIDCAuthEngineRole at the same mount.
	// +kubebuilder:validation:Optional
	DefaultRole string `json:"defaultRole,omitempty"`
}

// OpenBaoJWTOIDCAuthEngineConfigStatus defines the observed state.
type OpenBaoJWTOIDCAuthEngineConfigStatus struct {
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

	// ResolvedClientSecret holds the cleartext value
	// PrepareInternalValues pulled from spec.oidcClientSecretRef.
	// Surfaced for drift comparison only — the operator's status
	// store is the same etcd that would otherwise hold the inline
	// cleartext, so this is no worse than inlining; the Secret-ref
	// pattern is about not putting it in the CR YAML manifest.
	// +optional
	ResolvedClientSecret string `json:"resolvedClientSecret,omitempty"`
}

func (m *OpenBaoJWTOIDCAuthEngineConfig) GetConditions() []metav1.Condition {
	return m.Status.Conditions
}
func (m *OpenBaoJWTOIDCAuthEngineConfig) SetConditions(c []metav1.Condition) { m.Status.Conditions = c }
func (m *OpenBaoJWTOIDCAuthEngineConfig) IsBaoWritten() bool                 { return m.Status.BaoWritten }
func (m *OpenBaoJWTOIDCAuthEngineConfig) MarkBaoWritten()                    { m.Status.BaoWritten = true }
func (m *OpenBaoJWTOIDCAuthEngineConfig) LastWrittenBaoName() string {
	return m.Status.LastWrittenBaoName
}
func (m *OpenBaoJWTOIDCAuthEngineConfig) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}
func (m *OpenBaoJWTOIDCAuthEngineConfig) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=objwtcfg

// OpenBaoJWTOIDCAuthEngineConfig is the Schema for the
// openbaojwtoidcauthengineconfigs API.
type OpenBaoJWTOIDCAuthEngineConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoJWTOIDCAuthEngineConfigSpec   `json:"spec,omitempty"`
	Status OpenBaoJWTOIDCAuthEngineConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoJWTOIDCAuthEngineConfigList contains a list of
// OpenBaoJWTOIDCAuthEngineConfig.
type OpenBaoJWTOIDCAuthEngineConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoJWTOIDCAuthEngineConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoJWTOIDCAuthEngineConfig{}, &OpenBaoJWTOIDCAuthEngineConfigList{})
}
