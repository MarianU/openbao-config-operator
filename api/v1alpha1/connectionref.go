package v1alpha1

// ConnectionRef names the OpenBaoConnection CR a primitive CR uses to reach
// OpenBao. It is how every primitive selects which of the (potentially many,
// cluster-declared) OpenBao connections to talk to. The connection itself
// carries all transport/auth details; the reference just points at it so
// primitives stay free of any connection material.
//
// Require-explicit policy: a primitive with an empty/unset connectionRef is
// rejected as Invalid by the shared reconciler, so no CR silently falls back
// to a hidden global connection.
type ConnectionRef struct {
	// Name of the OpenBaoConnection CR. Required.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace of the OpenBaoConnection CR. Defaults to the referencing
	// CR's own namespace when omitted.
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`
}

// SecretRef points at a Kubernetes Secret (value kept out of the CR / Git).
// The operator reads the material at reconcile time.
type SecretRef struct {
	// Name of the Kubernetes Secret. Required.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Key within the Secret's data. Defaults per-use (e.g. "token" for an
	// auth token, "ca.crt" for a CA bundle, "tls.crt"/"tls.key" for a
	// client certificate pair).
	// +kubebuilder:validation:Optional
	Key string `json:"key,omitempty"`

	// Namespace of the Kubernetes Secret. Defaults to the connection CR's
	// own namespace when omitted.
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`
}
