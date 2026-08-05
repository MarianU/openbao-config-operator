// Adapted from redhat-cop/vault-config-operator
//
//	api/v1alpha1/jwtoidcauthenginerole_types.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b
//	<https://github.com/redhat-cop/vault-config-operator>
//
// Licensed under the Apache License, Version 2.0
// <https://www.apache.org/licenses/LICENSE-2.0>.
//
// Modifications relative to upstream:
//   - Kind renamed JWTOIDCAuthEngineRole → OpenBaoJWTOIDCAuthEngineRole.
//   - spec.openbaoNamespace added; spec.authentication / spec.connection
//     removed.
//   - Pairs with an OpenBaoAuthMethod of type=jwt or type=oidc at the
//     same path. The role binds inbound JWT/OIDC claims to bao
//     policies + identity.
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

// JWT/OIDC role types as bao expects on the wire.
const (
	JWTOIDCRoleTypeJWT  = "jwt"
	JWTOIDCRoleTypeOIDC = "oidc"
)

var _ vaultobject.VaultObject = &OpenBaoJWTOIDCAuthEngineRole{}
var _ vaultobject.ConditionsAware = &OpenBaoJWTOIDCAuthEngineRole{}
var _ vaultobject.WriteTracker = &OpenBaoJWTOIDCAuthEngineRole{}
var _ vaultobject.RenameTracker = &OpenBaoJWTOIDCAuthEngineRole{}

func (d *OpenBaoJWTOIDCAuthEngineRole) BaoName() string {
	raw := d.Spec.Name
	if raw == "" {
		raw = d.Name
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func (d *OpenBaoJWTOIDCAuthEngineRole) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

func (d *OpenBaoJWTOIDCAuthEngineRole) GetPath() string {
	return "auth/" + strings.Trim(d.Spec.Path, "/") + "/role/" + d.BaoName()
}

func (d *OpenBaoJWTOIDCAuthEngineRole) GetPayload() map[string]interface{} {
	return nil
}

func (d *OpenBaoJWTOIDCAuthEngineRole) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	cur, ok := payload["role"].(*baoclient.JWTOIDCRoleSpec)
	if !ok || cur == nil {
		return false
	}
	if d.Spec.RoleType != cur.RoleType {
		return false
	}
	if d.Spec.UserClaim != cur.UserClaim {
		return false
	}
	if !sortedEqual(d.Spec.BoundAudiences, cur.BoundAudiences) {
		return false
	}
	if d.Spec.BoundSubject != cur.BoundSubject {
		return false
	}
	if d.Spec.BoundClaimsType != cur.BoundClaimsType {
		return false
	}
	if !boundClaimsEqual(d.Spec.BoundClaims, cur.BoundClaims) {
		return false
	}
	if d.Spec.GroupsClaim != cur.GroupsClaim {
		return false
	}
	if !sortedEqual(d.Spec.OIDCScopes, cur.OIDCScopes) {
		return false
	}
	if !sortedEqual(d.Spec.AllowedRedirectURIs, cur.AllowedRedirectURIs) {
		return false
	}
	if !sortedEqual(d.Spec.TokenPolicies, cur.TokenPolicies) {
		return false
	}
	if !sortedEqual(d.Spec.TokenBoundCIDRs, cur.TokenBoundCIDRs) {
		return false
	}
	if !reflect.DeepEqual(stringMapOrNil(d.Spec.ClaimMappings), stringMapOrNil(cur.ClaimMappings)) {
		return false
	}
	desiredTTL := strings.TrimSpace(d.Spec.TokenTTL)
	if desiredTTL != "" && desiredTTL != cur.TokenTTL {
		return false
	}
	desiredMaxTTL := strings.TrimSpace(d.Spec.TokenMaxTTL)
	if desiredMaxTTL != "" && desiredMaxTTL != cur.TokenMaxTTL {
		return false
	}
	return true
}

func (d *OpenBaoJWTOIDCAuthEngineRole) IsInitialized() bool { return true }

func (d *OpenBaoJWTOIDCAuthEngineRole) IsDeletable() bool {
	return d.Spec.DeletionPolicy.DeletesGrantKind()
}

func (d *OpenBaoJWTOIDCAuthEngineRole) PrepareInternalValues(ctx context.Context, object client.Object) error {
	return nil
}
func (d *OpenBaoJWTOIDCAuthEngineRole) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoJWTOIDCAuthEngineRole) IsValid() (bool, error) {
	if d.BaoName() == "" {
		return false, fmt.Errorf("spec.name (or metadata.name) must not be empty")
	}
	if strings.TrimSpace(d.Spec.Path) == "" {
		return false, fmt.Errorf("spec.path must name a jwt or oidc auth mount")
	}
	if d.Spec.RoleType != JWTOIDCRoleTypeJWT && d.Spec.RoleType != JWTOIDCRoleTypeOIDC {
		return false, fmt.Errorf("spec.roleType %q is not valid; must be %q or %q",
			d.Spec.RoleType, JWTOIDCRoleTypeJWT, JWTOIDCRoleTypeOIDC)
	}
	if strings.TrimSpace(d.Spec.UserClaim) == "" {
		return false, fmt.Errorf("spec.userClaim must name a JWT claim bao maps to the entity name (e.g. \"sub\", \"email\")")
	}
	if d.Spec.RoleType == JWTOIDCRoleTypeOIDC && len(d.Spec.AllowedRedirectURIs) == 0 {
		return false, fmt.Errorf("spec.allowedRedirectUris must list at least one URI for type=oidc roles")
	}
	// Bao treats an empty-list bound-claim as "no value matches" — a
	// silent lockout for every inbound token whose claim names match
	// the empty list. Reject both the empty-key shape (no claim name)
	// and empty-value shape (no accepted values) at admission so the
	// failure surfaces as a config error instead of a login outage.
	for key, vals := range d.Spec.BoundClaims {
		if strings.TrimSpace(key) == "" {
			return false, fmt.Errorf("spec.boundClaims has an empty key; every entry must name a JWT claim")
		}
		if len(vals) == 0 {
			return false, fmt.Errorf(
				"spec.boundClaims[%q] is empty; an empty value list locks out every "+
					"login because no value can satisfy the filter — remove the key to disable the filter "+
					"or list at least one accepted value", key)
		}
	}
	return true, nil
}

func (d *OpenBaoJWTOIDCAuthEngineRole) ToBaoSpec() baoclient.JWTOIDCRoleSpec {
	return baoclient.JWTOIDCRoleSpec{
		RoleType:            d.Spec.RoleType,
		UserClaim:           d.Spec.UserClaim,
		BoundAudiences:      append([]string(nil), d.Spec.BoundAudiences...),
		BoundSubject:        d.Spec.BoundSubject,
		BoundClaimsType:     d.Spec.BoundClaimsType,
		BoundClaims:         boundClaimsToBao(d.Spec.BoundClaims),
		GroupsClaim:         d.Spec.GroupsClaim,
		ClaimMappings:       copyStringMapV1(d.Spec.ClaimMappings),
		OIDCScopes:          append([]string(nil), d.Spec.OIDCScopes...),
		AllowedRedirectURIs: append([]string(nil), d.Spec.AllowedRedirectURIs...),
		TokenPolicies:       append([]string(nil), d.Spec.TokenPolicies...),
		TokenTTL:            d.Spec.TokenTTL,
		TokenMaxTTL:         d.Spec.TokenMaxTTL,
		TokenBoundCIDRs:     append([]string(nil), d.Spec.TokenBoundCIDRs...),
	}
}

// boundClaimsToBao copies a typed (claim → list of strings) map into
// the loose map[string]interface{} the bao wire format expects.
// Returns nil for an empty input so the writer omits the field.
func boundClaimsToBao(in map[string][]string) map[string]interface{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// boundClaimsEqual compares the typed desired claims against bao's
// read (a map of interface{} values, since bao's bound_claims also
// supports comparison-operator objects like {"gt": 18}). The CRD
// shape only models the string/list case used for group + claim
// filtering, so a bao-side value that isn't string-coercible
// compares as a mismatch — which is the correct behaviour: an
// operator-edited bao value the CRD can't represent must trigger a
// rewrite back to the CR's intent.
func boundClaimsEqual(desired map[string][]string, current map[string]interface{}) bool {
	if len(desired) != len(current) {
		return false
	}
	for k, want := range desired {
		raw, ok := current[k]
		if !ok {
			return false
		}
		got, ok := boundClaimsCoerceList(raw)
		if !ok {
			return false
		}
		a := append([]string(nil), want...)
		b := append([]string(nil), got...)
		sort.Strings(a)
		sort.Strings(b)
		if !reflect.DeepEqual(a, b) {
			return false
		}
	}
	return true
}

// boundClaimsCoerceList accepts the shapes bao returns for a
// bound_claims value: a single string, a slice of strings, or a
// []interface{} of strings (encoding/json's default for JSON arrays).
// Returns ok=false for anything else.
func boundClaimsCoerceList(v interface{}) ([]string, bool) {
	switch t := v.(type) {
	case string:
		return []string{t}, true
	case []string:
		return t, true
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

// OpenBaoJWTOIDCAuthEngineRoleSpec defines the desired state.
type OpenBaoJWTOIDCAuthEngineRoleSpec struct {
	// DeletionPolicy controls what happens to the bao-side role when
	// this CR is deleted or its bao identity changes. Delete (the
	// default) removes the role, so new logins through it stop;
	// tokens already issued keep working until their TTL expires.
	// Retain releases the CR without touching bao — the role survives
	// as an intentional, logged orphan that no CR tracks afterward;
	// use only where rendering churn must never drop live access.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// Path is the bao-side jwt or oidc auth mount.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Path string `json:"path"`

	// Name is the bao-side role name. Defaults to metadata.name.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name,omitempty"`

	// OpenBaoNamespace targets a specific OpenBao namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// RoleType is "jwt" or "oidc". OIDC roles additionally require
	// allowedRedirectUris.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=jwt;oidc
	RoleType string `json:"roleType"`

	// UserClaim is the JWT claim bao uses as the identity entity
	// name (e.g. "sub", "email", "preferred_username").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	UserClaim string `json:"userClaim"`

	// BoundAudiences narrows accepted tokens to those whose "aud"
	// claim contains one of these values. Required for JWT roles
	// when no boundIssuer is set; OIDC roles use the client_id by
	// default.
	// +kubebuilder:validation:Optional
	BoundAudiences []string `json:"boundAudiences,omitempty"`

	// BoundSubject narrows by "sub" claim.
	// +kubebuilder:validation:Optional
	BoundSubject string `json:"boundSubject,omitempty"`

	// BoundClaimsType controls how BoundClaims values are matched
	// against inbound JWT claim values: "string" (default) for
	// exact-match, "glob" for shell-style wildcards.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=string;glob
	BoundClaimsType string `json:"boundClaimsType,omitempty"`

	// BoundClaims gates login on JWT claim values. Each key is a
	// claim name (e.g. "groups", "email"); the value is the list of
	// accepted strings. A login token must carry every listed claim
	// with a value matching one of the entries (interpretation
	// controlled by BoundClaimsType). Empty disables the filter —
	// any token passing BoundAudiences / BoundSubject is accepted.
	// +kubebuilder:validation:Optional
	BoundClaims map[string][]string `json:"boundClaims,omitempty"`

	// GroupsClaim is the JWT claim bao uses to populate the
	// identity's groups (mapped to bao identity groups via aliases).
	// +kubebuilder:validation:Optional
	GroupsClaim string `json:"groupsClaim,omitempty"`

	// ClaimMappings maps inbound JWT claim names to bao identity
	// metadata keys.
	// +kubebuilder:validation:Optional
	ClaimMappings map[string]string `json:"claimMappings,omitempty"`

	// OIDCScopes is the list of OIDC scopes bao requests on login.
	// +kubebuilder:validation:Optional
	OIDCScopes []string `json:"oidcScopes,omitempty"`

	// AllowedRedirectURIs is required for type=oidc roles. Bao
	// includes these in the authorization request's redirect_uri
	// list.
	// +kubebuilder:validation:Optional
	AllowedRedirectURIs []string `json:"allowedRedirectUris,omitempty"`

	// TokenPolicies is the list of bao policies granted on a
	// successful login.
	// +kubebuilder:validation:Optional
	TokenPolicies []string `json:"tokenPolicies,omitempty"`

	// TokenTTL / TokenMaxTTL are bao duration strings.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	TokenTTL string `json:"tokenTtl,omitempty"`
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([0-9]+(ns|us|ms|s|m|h|d))+$`
	TokenMaxTTL string `json:"tokenMaxTtl,omitempty"`

	// TokenBoundCIDRs restricts source IPs of subsequent token uses.
	// +kubebuilder:validation:Optional
	TokenBoundCIDRs []string `json:"tokenBoundCidrs,omitempty"`
}

// OpenBaoJWTOIDCAuthEngineRoleStatus defines the observed state.
type OpenBaoJWTOIDCAuthEngineRoleStatus struct {
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
	// +optional
	LastWrittenPath string `json:"lastWrittenPath,omitempty"`
}

func (m *OpenBaoJWTOIDCAuthEngineRole) GetConditions() []metav1.Condition  { return m.Status.Conditions }
func (m *OpenBaoJWTOIDCAuthEngineRole) SetConditions(c []metav1.Condition) { m.Status.Conditions = c }
func (m *OpenBaoJWTOIDCAuthEngineRole) IsBaoWritten() bool                 { return m.Status.BaoWritten }
func (m *OpenBaoJWTOIDCAuthEngineRole) MarkBaoWritten()                    { m.Status.BaoWritten = true }
func (m *OpenBaoJWTOIDCAuthEngineRole) LastWrittenBaoName() string {
	return m.Status.LastWrittenBaoName
}
func (m *OpenBaoJWTOIDCAuthEngineRole) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}
func (m *OpenBaoJWTOIDCAuthEngineRole) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=objwtrole

// OpenBaoJWTOIDCAuthEngineRole is the Schema for the
// openbaojwtoidcauthengineroles API.
type OpenBaoJWTOIDCAuthEngineRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoJWTOIDCAuthEngineRoleSpec   `json:"spec,omitempty"`
	Status OpenBaoJWTOIDCAuthEngineRoleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoJWTOIDCAuthEngineRoleList contains a list of
// OpenBaoJWTOIDCAuthEngineRole.
type OpenBaoJWTOIDCAuthEngineRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoJWTOIDCAuthEngineRole `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoJWTOIDCAuthEngineRole{}, &OpenBaoJWTOIDCAuthEngineRoleList{})
}
