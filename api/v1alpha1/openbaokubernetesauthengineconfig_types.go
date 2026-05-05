// Adapted from redhat-cop/vault-config-operator
//
//	api/v1alpha1/kubernetesauthengineconfig_types.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b
//	<https://github.com/redhat-cop/vault-config-operator>
//
// Licensed under the Apache License, Version 2.0
// <https://www.apache.org/licenses/LICENSE-2.0>.
//
// Modifications relative to upstream:
//   - Kind renamed KubernetesAuthEngineConfig → OpenBaoKubernetesAuthEngineConfig.
//   - spec.openbaoNamespace added; spec.authentication / spec.connection
//     removed.
//   - Token-reviewer JWT and CA cert come from Kubernetes Secrets via
//     spec.tokenReviewerJwtRef / spec.kubernetesCaCertRef. The cleartext
//     values never appear in the CR spec; PrepareInternalValues resolves
//     them at reconcile time. This replaces upstream's
//     spec.tokenReviewerServiceAccount auto-mint flow — users provide an
//     existing Secret, and the Secret-watch propagates rotations.
//   - Pairs with an OpenBaoAuthMethod of type=kubernetes at spec.path.
//     Mount lifecycle is owned by the auth-method controller; this CRD
//     only writes auth/<mount>/config.
package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject"
)

var _ vaultobject.VaultObject = &OpenBaoKubernetesAuthEngineConfig{}
var _ vaultobject.ConditionsAware = &OpenBaoKubernetesAuthEngineConfig{}
var _ vaultobject.WriteTracker = &OpenBaoKubernetesAuthEngineConfig{}
var _ vaultobject.RenameTracker = &OpenBaoKubernetesAuthEngineConfig{}

// BaoName returns the bao-side kubernetes auth mount path. Kubernetes
// auth config is mount-singleton, so the "name" is just the mount path.
func (d *OpenBaoKubernetesAuthEngineConfig) BaoName() string {
	return strings.Trim(d.Spec.Path, "/")
}

func (d *OpenBaoKubernetesAuthEngineConfig) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

func (d *OpenBaoKubernetesAuthEngineConfig) GetPath() string {
	return "auth/" + strings.Trim(d.Spec.Path, "/") + "/config"
}

func (d *OpenBaoKubernetesAuthEngineConfig) GetPayload() map[string]interface{} {
	return nil
}

// IsEquivalentToDesiredState compares the spec against the bao read.
// String fields with empty desired adopt bao's value (no drift). Bool
// pointer fields nil-on-spec adopt bao's value too. Slices are sorted
// before compare.
//
// Secret-sourced fields (token_reviewer_jwt, kubernetes_ca_cert) cannot
// be compared against bao directly: bao redacts both on read. The
// reconciler stamps an HMAC of the resolved values onto status under
// the payload keys "currentSecretMAC" (this reconcile pass) and
// "lastWrittenSecretMAC" (from the previous successful write); a
// mismatch signals rotation. See [internal/hmacstore](../../internal/hmacstore).
//
// Trade-off: out-of-band edits to the bao-side JWT or CA cert are not
// detected, because bao won't return the values to compare against.
// Rotation through the k8s Secret IS detected. That's the reverse of
// the previous "both non-empty" guard, which detected OOB edits but
// missed rotation — and rotation is the common operational flow.
func (d *OpenBaoKubernetesAuthEngineConfig) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	cur, ok := payload["config"].(*baoclient.K8sAuthConfigSpec)
	if !ok || cur == nil {
		return false
	}
	curMAC, _ := payload["currentSecretMAC"].(string)
	lastMAC, _ := payload["lastWrittenSecretMAC"].(string)
	if curMAC != lastMAC {
		return false
	}
	if !stringEqualOrAdopt(d.Spec.KubernetesHost, cur.KubernetesHost) {
		return false
	}
	if !sortedSliceEqualOrEmpty(d.Spec.PEMKeys, cur.PEMKeys) {
		return false
	}
	if !stringEqualOrAdopt(d.Spec.Issuer, cur.Issuer) {
		return false
	}
	if !boolPtrEq(d.Spec.DisableISSValidation, cur.DisableISSValidation) {
		return false
	}
	if !boolPtrEq(d.Spec.DisableLocalCAJWT, cur.DisableLocalCAJWT) {
		return false
	}
	if !boolPtrEq(d.Spec.UseAnnotationsAsAliasMetadata, cur.UseAnnotationsAsAliasMetadata) {
		return false
	}
	return true
}

// SecretMACInputs returns the byte slices an HMAC computer should
// digest for this CR's Secret-sourced fields, in stable order. Used
// by the controller to compute currentSecretMAC and to set
// lastWrittenSecretMAC on a successful write.
func (d *OpenBaoKubernetesAuthEngineConfig) SecretMACInputs() [][]byte {
	return [][]byte{
		[]byte(d.Status.ResolvedTokenReviewerJWT),
		[]byte(d.Status.ResolvedKubernetesCACert),
	}
}

func (d *OpenBaoKubernetesAuthEngineConfig) IsInitialized() bool { return true }

// IsDeletable returns false: bao's auth/<mount>/config has no DELETE
// endpoint. Removing the CR releases the finalizer without touching bao.
func (d *OpenBaoKubernetesAuthEngineConfig) IsDeletable() bool { return false }

// PrepareInternalValues resolves spec.tokenReviewerJwtRef and
// spec.kubernetesCaCertRef into the bao-wire token_reviewer_jwt /
// kubernetes_ca_cert. Empty refs leave the resolved status fields
// unset; the spec just doesn't carry that field on the wire.
func (d *OpenBaoKubernetesAuthEngineConfig) PrepareInternalValues(ctx context.Context, object client.Object) error {
	d.Status.ResolvedTokenReviewerJWT = ""
	d.Status.ResolvedKubernetesCACert = ""

	if d.Spec.TokenReviewerJwtRef == nil && d.Spec.KubernetesCaCertRef == nil {
		return nil
	}
	//nolint:staticcheck // matches the shared base contract
	cl, ok := ctx.Value("kubeClient").(client.Client)
	if !ok || cl == nil {
		return fmt.Errorf("kube client not available in reconcile context")
	}
	if d.Spec.TokenReviewerJwtRef != nil {
		val, err := readSecretRef(ctx, cl, d.Namespace, d.Spec.TokenReviewerJwtRef.Name,
			d.Spec.TokenReviewerJwtRef.Namespace, d.Spec.TokenReviewerJwtRef.Key, "token")
		if err != nil {
			return fmt.Errorf("loading token reviewer JWT: %w", err)
		}
		d.Status.ResolvedTokenReviewerJWT = val
	}
	if d.Spec.KubernetesCaCertRef != nil {
		val, err := readSecretRef(ctx, cl, d.Namespace, d.Spec.KubernetesCaCertRef.Name,
			d.Spec.KubernetesCaCertRef.Namespace, d.Spec.KubernetesCaCertRef.Key, "ca.crt")
		if err != nil {
			return fmt.Errorf("loading kubernetes CA cert: %w", err)
		}
		d.Status.ResolvedKubernetesCACert = val
	}
	return nil
}

func readSecretRef(ctx context.Context, cl client.Client, defaultNS, name, refNS, key, defaultKey string) (string, error) {
	ns := strings.TrimSpace(refNS)
	if ns == "" {
		ns = defaultNS
	}
	n := strings.TrimSpace(name)
	if n == "" {
		return "", fmt.Errorf("Secret ref name must not be empty")
	}
	k := key
	if k == "" {
		k = defaultKey
	}
	var sec corev1.Secret
	if err := cl.Get(ctx, types.NamespacedName{Namespace: ns, Name: n}, &sec); err != nil {
		return "", fmt.Errorf("getting Secret %s/%s: %w", ns, n, err)
	}
	body, ok := sec.Data[k]
	if !ok || len(body) == 0 {
		return "", fmt.Errorf("Secret %s/%s key %q is empty or missing", ns, n, k)
	}
	return string(body), nil
}

func (d *OpenBaoKubernetesAuthEngineConfig) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoKubernetesAuthEngineConfig) IsValid() (bool, error) {
	if strings.TrimSpace(d.Spec.Path) == "" {
		return false, fmt.Errorf("spec.path must name a kubernetes auth mount")
	}
	if strings.TrimSpace(d.Spec.KubernetesHost) == "" {
		return false, fmt.Errorf("spec.kubernetesHost must be set (apiserver URL bao calls TokenReview against)")
	}
	if d.Spec.TokenReviewerJwtRef != nil && strings.TrimSpace(d.Spec.TokenReviewerJwtRef.Name) == "" {
		return false, fmt.Errorf("spec.tokenReviewerJwtRef.name must not be empty")
	}
	if d.Spec.KubernetesCaCertRef != nil && strings.TrimSpace(d.Spec.KubernetesCaCertRef.Name) == "" {
		return false, fmt.Errorf("spec.kubernetesCaCertRef.name must not be empty")
	}
	return true, nil
}

func (d *OpenBaoKubernetesAuthEngineConfig) ToBaoSpec() baoclient.K8sAuthConfigSpec {
	return baoclient.K8sAuthConfigSpec{
		KubernetesHost:                d.Spec.KubernetesHost,
		KubernetesCACert:              d.Status.ResolvedKubernetesCACert,
		TokenReviewerJWT:              d.Status.ResolvedTokenReviewerJWT,
		PEMKeys:                       append([]string(nil), d.Spec.PEMKeys...),
		Issuer:                        d.Spec.Issuer,
		DisableISSValidation:          d.Spec.DisableISSValidation,
		DisableLocalCAJWT:             d.Spec.DisableLocalCAJWT,
		UseAnnotationsAsAliasMetadata: d.Spec.UseAnnotationsAsAliasMetadata,
	}
}

// KubernetesTokenReviewerSecretRef points at a Kubernetes Secret
// holding the SA JWT bao presents to the apiserver when calling
// TokenReview. The Secret is read on every reconcile; a rotation
// re-enqueues the CR via the Secret watch.
type KubernetesTokenReviewerSecretRef struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`

	// Key inside the Secret. Defaults to "token" (matches the
	// service-account-token Secret type's key).
	// +kubebuilder:validation:Optional
	Key string `json:"key,omitempty"`
}

// KubernetesCaSecretRef points at a Kubernetes Secret holding the CA
// bundle bao uses to verify the apiserver's TLS cert.
type KubernetesCaSecretRef struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`

	// Key inside the Secret. Defaults to "ca.crt".
	// +kubebuilder:validation:Optional
	Key string `json:"key,omitempty"`
}

// OpenBaoKubernetesAuthEngineConfigSpec defines the desired state.
type OpenBaoKubernetesAuthEngineConfigSpec struct {
	// Path is the bao-side kubernetes auth mount path (e.g.
	// "kubernetes"). Pairs with an OpenBaoAuthMethod of
	// type=kubernetes at the same path.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Path string `json:"path"`

	// OpenBaoNamespace targets a specific OpenBao namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// KubernetesHost is the apiserver URL bao calls TokenReview
	// against on inbound login. Required.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	KubernetesHost string `json:"kubernetesHost"`

	// KubernetesCaCertRef points at a Secret holding the PEM-encoded
	// CA bundle that verifies the apiserver's TLS cert. Optional —
	// bao falls back to the system trust store if unset.
	// +kubebuilder:validation:Optional
	KubernetesCaCertRef *KubernetesCaSecretRef `json:"kubernetesCaCertRef,omitempty"`

	// TokenReviewerJwtRef points at a Secret holding the SA JWT bao
	// presents to the apiserver when calling TokenReview. Optional —
	// when unset, bao falls back to using the inbound login JWT
	// itself for the TokenReview call (works only on clusters that
	// allow self-review). Required for non-root mounts in practice.
	// +kubebuilder:validation:Optional
	TokenReviewerJwtRef *KubernetesTokenReviewerSecretRef `json:"tokenReviewerJwtRef,omitempty"`

	// PEMKeys is a list of PEM-encoded public keys bao verifies SA
	// JWT signatures against locally. Mutually-exclusive in practice
	// with the TokenReview flow; almost always empty.
	// +kubebuilder:validation:Optional
	PEMKeys []string `json:"pemKeys,omitempty"`

	// Issuer narrows accepted tokens to those whose "iss" claim
	// matches. Defaults to bao's "kubernetes/serviceaccount" when
	// unset.
	// +kubebuilder:validation:Optional
	Issuer string `json:"issuer,omitempty"`

	// DisableISSValidation skips JWT iss-claim validation. Set true
	// when the cluster issues SA tokens with an iss bao does not
	// trust (common with kind / minikube). Defaults to bao's setting
	// (typically false).
	// +kubebuilder:validation:Optional
	DisableISSValidation *bool `json:"disableIssValidation,omitempty"`

	// DisableLocalCAJWT disables defaulting to the local CA cert and
	// service-account JWT when bao runs inside a Kubernetes pod.
	// +kubebuilder:validation:Optional
	DisableLocalCAJWT *bool `json:"disableLocalCaJwt,omitempty"`

	// UseAnnotationsAsAliasMetadata copies SA annotations prefixed
	// with vault.hashicorp.com/alias-metadata- onto the bao identity
	// alias.
	// +kubebuilder:validation:Optional
	UseAnnotationsAsAliasMetadata *bool `json:"useAnnotationsAsAliasMetadata,omitempty"`
}

// OpenBaoKubernetesAuthEngineConfigStatus defines the observed state.
type OpenBaoKubernetesAuthEngineConfigStatus struct {
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

	// ResolvedTokenReviewerJWT holds the cleartext value
	// PrepareInternalValues pulled from spec.tokenReviewerJwtRef.
	// Surfaced for drift comparison only — same etcd-storage
	// trade-off as JWT/OIDC config's ResolvedClientSecret.
	// +optional
	ResolvedTokenReviewerJWT string `json:"resolvedTokenReviewerJwt,omitempty"`

	// ResolvedKubernetesCACert holds the PEM CA bundle resolved from
	// spec.kubernetesCaCertRef.
	// +optional
	ResolvedKubernetesCACert string `json:"resolvedKubernetesCaCert,omitempty"`

	// LastWrittenSecretMAC is the HMAC-SHA256 (base64) of the
	// Secret-sourced field values the operator last successfully wrote
	// to bao. The drift comparator compares the freshly-recomputed MAC
	// against this on each reconcile; a mismatch signals that the
	// underlying Secret rotated and the operator must re-write.
	// Empty until the first successful write. See [hmacstore](../../internal/hmacstore).
	// +optional
	LastWrittenSecretMAC string `json:"lastWrittenSecretMac,omitempty"`
}

func (m *OpenBaoKubernetesAuthEngineConfig) GetConditions() []metav1.Condition {
	return m.Status.Conditions
}
func (m *OpenBaoKubernetesAuthEngineConfig) SetConditions(c []metav1.Condition) {
	m.Status.Conditions = c
}
func (m *OpenBaoKubernetesAuthEngineConfig) IsBaoWritten() bool { return m.Status.BaoWritten }
func (m *OpenBaoKubernetesAuthEngineConfig) MarkBaoWritten()    { m.Status.BaoWritten = true }
func (m *OpenBaoKubernetesAuthEngineConfig) LastWrittenBaoName() string {
	return m.Status.LastWrittenBaoName
}
func (m *OpenBaoKubernetesAuthEngineConfig) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}
func (m *OpenBaoKubernetesAuthEngineConfig) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obkac

// OpenBaoKubernetesAuthEngineConfig is the Schema for the
// openbaokubernetesauthengineconfigs API.
type OpenBaoKubernetesAuthEngineConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoKubernetesAuthEngineConfigSpec   `json:"spec,omitempty"`
	Status OpenBaoKubernetesAuthEngineConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoKubernetesAuthEngineConfigList contains a list of
// OpenBaoKubernetesAuthEngineConfig.
type OpenBaoKubernetesAuthEngineConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoKubernetesAuthEngineConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoKubernetesAuthEngineConfig{}, &OpenBaoKubernetesAuthEngineConfigList{})
}
