// OpenBaoConnection defines how the operator reaches one OpenBao instance.
// It centralises every transport + auth parameter (`address`, TLS trust/SNI,
// client mTLS, and either a static token or a kubernetes-auth SA login) into
// a single named CR. All other OpenBao* CRDs reference one by name via
// spec.connectionRef, so a single operator process can manage many OpenBao
// instances with per-connection credentials — no more one-global-client-from-env.
//
// Secrets (server CA, client cert/key, auth token) are never inline: they are
// referenced via k8s SecretRef and read at reconcile time, keeping material
// out of Git. This follows the repo's standing no-secrets-in-git posture.
//
// OpenBaoConnection is a CONFIG / health kind, NOT a vault-object writer: it
// does not represent an object written into OpenBao (no bao path/payload), so
// it has no deletionPolicy and is not driven by the shared VaultResource
// write engine. Its controller builds a client from the resolved spec and
// performs a lookup-self auth probe, reporting connectivity + auth via
// status.conditions (Ready/Synced) and token TTL.
package v1alpha1

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stakater/openbao-config-operator/internal/vaultobject"
)

const (
	// AuthMethodKubernetes logs in via the operator pod's projected
	// ServiceAccount token at auth/<mount>/login.
	AuthMethodKubernetes = "kubernetes"
	// AuthMethodToken uses a static token from a referenced Secret.
	AuthMethodToken = "token"

	// DefaultKubernetesAuthMount is the kubernetes-auth mount the operator's
	// own login role lives under, matching the in-cluster deployment default.
	DefaultKubernetesAuthMount = "k8s-operator"
	// DefaultJWTPath is where the deployment mounts the projected SA token
	// (audience-bound to bao, distinct from the default API-server audience).
	DefaultJWTPath = "/var/run/secrets/openbao/token"
)

var _ vaultobject.ConditionsAware = &OpenBaoConnection{}

// OpenBaoConnectionSpec defines the desired state of OpenBaoConnection.
type OpenBaoConnectionSpec struct {
	// Address is the base URL of the OpenBao server, e.g.
	// https://bao.k8s.hostingpro.ro:8200. Required.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Address string `json:"address"`

	// TLS carries trust + client-mTLS parameters for the connection.
	// +kubebuilder:validation:Optional
	TLS OpenBaoConnectionTLS `json:"tls,omitempty"`

	// Auth describes how the operator authenticates to OpenBao.
	// +kubebuilder:validation:Required
	Auth OpenBaoConnectionAuth `json:"auth"`

	// OpenBaoNamespace is the default OpenBao namespace (X-Vault-Namespace)
	// applied to calls made through this connection when the referencing CR
	// does not set its own. Empty = root namespace.
	// +kubebuilder:validation:Optional
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`
}

// OpenBaoConnectionAuth is a discriminated union — exactly one of Kubernetes
// or Token must be set, selected by Method.
type OpenBaoConnectionAuth struct {
	// Method selects the auth mode: "kubernetes" (SA login) or "token"
	// (static token from a referenced Secret). Required.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=kubernetes;token
	Method string `json:"method"`

	// Kubernetes configures the kubernetes-auth login. Required when
	// method=kubernetes.
	// +kubebuilder:validation:Optional
	Kubernetes *OpenBaoKubernetesAuth `json:"kubernetes,omitempty"`

	// Token configures a static-token connection. Required when
	// method=token.
	// +kubebuilder:validation:Optional
	Token *OpenBaoTokenAuth `json:"token,omitempty"`
}

// OpenBaoKubernetesAuth configures the kubernetes-auth SA login. All paths
// reference the operator pod's own projected ServiceAccount token.
type OpenBaoKubernetesAuth struct {
	// Mount is the kubernetes auth mount to log in against. Defaults to
	// "k8s-operator".
	// +kubebuilder:validation:Optional
	Mount string `json:"mount,omitempty"`

	// Role is the login role to request (must be bound to the operator's
	// ServiceAccount). Required.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Role string `json:"role"`

	// JWTPath is the filesystem path of the projected ServiceAccount token.
	// Defaults to /var/run/secrets/openbao/token.
	// +kubebuilder:validation:Optional
	JWTPath string `json:"jwtPath,omitempty"`
}

// OpenBaoTokenAuth configures a static-token connection.
type OpenBaoTokenAuth struct {
	// TokenSecretRef references a Kubernetes Secret holding the token under
	// its `token` key (or `key`). Material is read at reconcile time; never
	// stored inline.
	// +kubebuilder:validation:Required
	TokenSecretRef SecretRef `json:"tokenSecretRef"`
}

// OpenBaoConnectionTLS configures trust + client certificates for the
// connection. All material comes from Kubernetes Secrets (never inline).
type OpenBaoConnectionTLS struct {
	// CACertSecretRef references a Secret holding the server CA bundle under
	// `ca.crt` (or `key`), used to verify the OpenBao server certificate.
	// Omitted = system root store.
	// +kubebuilder:validation:Optional
	CACertSecretRef *SecretRef `json:"caCertSecretRef,omitempty"`

	// ClientCertSecretRef references a Kubernetes tls-type Secret holding a
	// client certificate+key pair (tls.crt / tls.key) used for mutual TLS.
	// Omitted = no client cert.
	// +kubebuilder:validation:Optional
	ClientCertSecretRef *SecretRef `json:"clientCertSecretRef,omitempty"`

	// TLSServerName overrides the SNI / hostname used to verify the server
	// certificate (the internal CA may present a name different from the
	// address host). Omitted = derived from the address host.
	// +kubebuilder:validation:Optional
	TLSServerName string `json:"tlsServerName,omitempty"`

	// Insecure disables server-certificate verification. Intended only for
	// non-production / plaintext-dev boxes. Defaults false.
	// +kubebuilder:validation:Optional
	Insecure bool `json:"insecure,omitempty"`
}

// OpenBaoConnectionStatus defines the observed state of OpenBaoConnection.
type OpenBaoConnectionStatus struct {
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// ObservedGeneration is the last spec generation successfully
	// health-checked.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Authenticated reports whether the last health probe successfully
	// authenticated and reached OpenBao.
	// +optional
	Authenticated bool `json:"authenticated,omitempty"`

	// Version is the OpenBao server version reported by the last successful
	// probe, when available.
	// +optional
	Version string `json:"version,omitempty"`

	// TokenTTLSeconds is the remaining TTL of the authenticated token in
	// seconds, as of the last probe. 0 = non-expiring token.
	// +optional
	TokenTTLSeconds int64 `json:"tokenTTLSeconds,omitempty"`
}

func (m *OpenBaoConnection) GetConditions() []metav1.Condition {
	return m.Status.Conditions
}

func (m *OpenBaoConnection) SetConditions(conditions []metav1.Condition) {
	m.Status.Conditions = conditions
}

// AuthMount returns the effective kubernetes auth mount (defaulted).
func (s *OpenBaoConnectionSpec) AuthMount() string {
	if s.Auth.Kubernetes != nil && strings.TrimSpace(s.Auth.Kubernetes.Mount) != "" {
		return strings.Trim(s.Auth.Kubernetes.Mount, "/")
	}
	return DefaultKubernetesAuthMount
}

// AuthJWTPath returns the effective projected-SA-token path (defaulted).
func (s *OpenBaoConnectionSpec) AuthJWTPath() string {
	if s.Auth.Kubernetes != nil && strings.TrimSpace(s.Auth.Kubernetes.JWTPath) != "" {
		return s.Auth.Kubernetes.JWTPath
	}
	return DefaultJWTPath
}

// ResolvedNamespace returns the k8s namespace a SecretRef resolves in,
// defaulting to the connection's own namespace.
func (c *OpenBaoConnection) ResolvedNamespace(ref *SecretRef) string {
	if ref == nil {
		return c.Namespace
	}
	if ref.Namespace != "" {
		return ref.Namespace
	}
	return c.Namespace
}

// IsValid validates the discriminated auth union and required fields.
func (c *OpenBaoConnection) IsValid() (bool, error) {
	if strings.TrimSpace(c.Spec.Address) == "" {
		return false, fmt.Errorf("spec.address must not be empty")
	}
	switch c.Spec.Auth.Method {
	case AuthMethodKubernetes:
		if c.Spec.Auth.Kubernetes == nil {
			return false, fmt.Errorf("spec.auth.method=%q requires spec.auth.kubernetes", AuthMethodKubernetes)
		}
		if strings.TrimSpace(c.Spec.Auth.Kubernetes.Role) == "" {
			return false, fmt.Errorf("spec.auth.kubernetes.role must not be empty")
		}
	case AuthMethodToken:
		if c.Spec.Auth.Token == nil {
			return false, fmt.Errorf("spec.auth.method=%q requires spec.auth.token", AuthMethodToken)
		}
		if strings.TrimSpace(c.Spec.Auth.Token.TokenSecretRef.Name) == "" {
			return false, fmt.Errorf("spec.auth.token.tokenSecretRef.name must not be empty")
		}
	default:
		return false, fmt.Errorf("spec.auth.method must be %q or %q, got %q",
			AuthMethodKubernetes, AuthMethodToken, c.Spec.Auth.Method)
	}
	return true, nil
}

// ConnectionRef returns the connection this CR is itself (it is referenced by
// name, so it exposes nil here — it is the connection, not a consumer). Kept
// for interface uniformity is unnecessary; this method is intentionally
// absent from the ConnectionReferer contract.

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obc

// OpenBaoConnection is the Schema for the openbaoconnections API.
type OpenBaoConnection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoConnectionSpec   `json:"spec,omitempty"`
	Status OpenBaoConnectionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoConnectionList contains a list of OpenBaoConnection.
type OpenBaoConnectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoConnection `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoConnection{}, &OpenBaoConnectionList{})
}

// Ensure OpenBaoConnection satisfies client.Object without importing clash.
var _ client.Object = &OpenBaoConnection{}
