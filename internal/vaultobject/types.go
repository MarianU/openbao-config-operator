package vaultobject

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// KubeAuthConfiguration and VaultConnection below are carried for
// VCO-interface parity. Our operator ignores them — the shared token from
// OpenBaoExtension is always used, per the roadmap's Decisions. The strip
// happens when each primitive's type file is copied; the struct definitions
// remain here so copied methods that reference them compile.

// Path is a string alias used by VCO-origin fields that name a Vault
// logical path (auth mounts, secret engine paths). The regex mirrors VCO
// upstream; it accepts the leading slash / trailing slash / empty path
// forms VCO emits.
//
// +kubebuilder:validation:Pattern:=`^(?:/?[\w;:@&=\$-\.\+]*)+/?`
type Path string

// +kubebuilder:object:generate=true
type KubeAuthConfiguration struct {
	// ServiceAccount is the service account used for the kube auth
	// authentication.
	// +kubebuilder:validation:Required
	// +kubebuilder:default={"name": "default"}
	ServiceAccount *corev1.LocalObjectReference `json:"serviceAccount,omitempty"`

	// Path is the path of the role used for this kube auth authentication.
	// +kubebuilder:validation:Required
	// +kubebuilder:default=kubernetes
	Path Path `json:"path,omitempty"`

	// Role is the role used during authentication.
	// +kubebuilder:validation:Required
	Role string `json:"role,omitempty"`

	// Namespace is the Vault namespace used for all operations in this
	// connection/authentication. Vault Enterprise only.
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`
}

// +kubebuilder:object:generate=true
type TLSConfig struct {
	// Cacert is the path to a PEM-encoded CA certificate file on the local
	// disk used to verify the Vault server's SSL certificate.
	// +kubebuilder:validation:Optional
	Cacert *string `json:"cacert,omitempty"`

	// TLSSecret is a namespace-local secret containing the TLS material.
	// Expected keys: ca.crt, tls.crt, tls.key.
	// +kubebuilder:validation:Optional
	TLSSecret *corev1.LocalObjectReference `json:"tlsSecret,omitempty"`

	// SkipVerify disables server TLS verification. Not recommended.
	// +kubebuilder:validation:Optional
	SkipVerify bool `json:"skipVerify,omitempty"`

	// TLSServerName is the SNI host used when connecting via TLS.
	// +kubebuilder:validation:Optional
	TLSServerName *string `json:"tlsServerName,omitempty"`
}

// +kubebuilder:object:generate=true
type VaultConnection struct {
	// +kubebuilder:validation:Optional
	TLSConfig *TLSConfig `json:"tLSConfig,omitempty"`

	// Address of the Vault server, e.g. https://127.0.0.1:8200/.
	// +kubebuilder:validation:Required
	Address string `json:"address,omitempty"`

	// TimeOut defaults to 60s.
	// +kubebuilder:validation:Optional
	TimeOut *metav1.Duration `json:"timeOut,omitempty"`

	// MaxRetries — default 2, for three total attempts. Set ≤ 0 to disable
	// retrying. Retries apply to 412 and 5xx except 501.
	// +kubebuilder:validation:Optional
	MaxRetries *int `json:"maxRetries,omitempty"`
}

// +kubebuilder:object:generate=true
type VaultSecretReference struct {
	// Path is the path to the secret in Vault.
	// +kubebuilder:validation:Required
	Path string `json:"path,omitempty"`
}

// +kubebuilder:object:generate=true
type RootCredentialConfig struct {
	// VaultSecret retrieves the credentials from a Vault secret. Maps
	// "username" and "password" keys. Exactly one of VaultSecret / Secret /
	// RandomSecret must be specified.
	// +kubebuilder:validation:Optional
	VaultSecret *VaultSecretReference `json:"vaultSecret,omitempty"`

	// Secret retrieves the credentials from a Kubernetes basic-auth secret.
	// +kubebuilder:validation:Optional
	Secret *corev1.LocalObjectReference `json:"secret,omitempty"`

	// RandomSecret retrieves the credentials from a RandomSecret CR.
	// +kubebuilder:validation:Optional
	RandomSecret *corev1.LocalObjectReference `json:"randomSecret,omitempty"`

	// PasswordKey used when retrieving the password; required with
	// VaultSecret and Secret, ignored with RandomSecret.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="password"
	PasswordKey string `json:"passwordKey,omitempty"`

	// UsernameKey used when retrieving the username; optional with
	// VaultSecret and Secret, ignored with RandomSecret.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="username"
	UsernameKey string `json:"usernameKey,omitempty"`
}

// +kubebuilder:object:generate=true
type TargetNamespaceConfig struct {
	// TargetNamespaceSelector picks namespaces by label. Either this or
	// TargetNamespaces must be set (not both).
	// +kubebuilder:validation:Optional
	TargetNamespaceSelector *metav1.LabelSelector `json:"targetNamespaceSelector,omitempty"`

	// TargetNamespaces is an explicit list. Either this or
	// TargetNamespaceSelector must be set (not both).
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	TargetNamespaces []string `json:"targetNamespaces,omitempty"`
}
