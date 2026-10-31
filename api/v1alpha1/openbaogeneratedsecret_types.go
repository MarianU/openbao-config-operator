// OpenBaoGeneratedSecret is a new kind added in the MarianU fork. It makes
// OpenBao the system of record for a randomly generated secret, so two or
// more consumers can share the same value without anyone ever setting it.
//
// The operator generates a cryptographically random value (crypto/rand,
// charset + length from spec.generator), writes it to an OpenBao KVv2
// engine at <mount>/data/<path>, and regenerates + rewrites it once
// spec.rotationPeriod elapses since the last rotation. Each write bumps the
// KVv2 version; on the read side, VSO (unchanged) syncs the path to each
// consumer's Kubernetes Secret, and a Reloader/restart-on-change makes the
// deployments rotate when the value changes — mirroring the database-password
// pattern where OpenBao holds and rotates the value and nothing is committed
// to Git.
//
// The operator owns the rotation clock: OpenBao itself cannot re-randomize a
// stored KVv2 value on a timer (KVv2 has no TTL/rotation concept; only the
// database static-role and dynamic-lease engines rotate natively, and those
// are DB-bound). So this kind is the generic, non-DB generalization of that
// pattern. With rotationPeriod 0 the value is generated once and never
// rotated.
//
// On-demand rotation: set the RotationAnnotationKey annotation to a fresh,
// non-empty value (e.g. a timestamp) to force an immediate rotation without
// changing the spec. Each new value rotates exactly once; repeating the
// same value is a no-op (the controller records the last-processed token in
// status.lastRequestedRotation). The value is never persisted on the CR.
// The generated value is never persisted on the CR — it lives only in the
// CR's spec (the generation policy) and in OpenBao. Consumers read it from
// OpenBao via VSO, never from this CR. Git holds the policy + path, never
// the value.
//
// Safety: the value is data-bearing, so deletionPolicy default is Retain —
// deleting the CR does NOT delete the secret unless the operator opts in
// (deletesDataKind reading).
package v1alpha1

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stakater/openbao-config-operator/internal/vaultobject"
)

// Supported generator charsets.
const (
	CharsetAlphaNumSpecial = "alphaNumSpecial"
	CharsetAlphaNum        = "alphaNum"
	CharsetAlpha           = "alpha"
	CharsetNumeric         = "numeric"
	CharsetHex             = "hex"
	CharsetLower           = "lower"
	CharsetUpper           = "upper"
)

const (
	genLower   = "abcdefghijklmnopqrstuvwxyz"
	genUpper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	genDigits  = "0123456789"
	genSymbols = "!@#$%^&*()-_=+[]{};:,.<>?"
)

// RotationAnnotationKey is the annotation used to request an on-demand
// rotation of an OpenBaoGeneratedSecret. Set it to a fresh, non-empty value
// (e.g. `kubectl annotate <cr> security.mto.stakater.com/rotate=$(date
// +%s)`) to force an immediate regenerate + rewrite. Each new value rotates
// once; an empty or previously-processed value is ignored. Reconciles are
// near-immediate because the controller's event filter also observes
// annotation changes.
const RotationAnnotationKey = "security.mto.stakater.com/rotate"

var _ vaultobject.VaultObject = &OpenBaoGeneratedSecret{}
var _ vaultobject.ConditionsAware = &OpenBaoGeneratedSecret{}
var _ vaultobject.WriteTracker = &OpenBaoGeneratedSecret{}
var _ vaultobject.RenameTracker = &OpenBaoGeneratedSecret{}

// OpenBaoGeneratedSecretSpec defines the desired state.
type OpenBaoGeneratedSecretSpec struct {
	// DeletionPolicy controls what happens to the bao-side secret when this
	// CR is deleted. Retain (the default) orphans the secret; Delete removes
	// it. The value is data-bearing, so the fail-safe direction is Retain.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=Retain
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// Mount is the KVv2 secret-engine mount path. Defaults to "secret".
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	// +kubebuilder:default="secret"
	Mount string `json:"mount,omitempty"`

	// Path is the secret's key path within the mount (e.g. "apps/db/admin").
	// The full bao path is <mount>/data/<path>. Defaults to metadata.name.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Path string `json:"path"`

	// OpenBaoNamespace targets a bao namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// RotationPeriod is how long OpenBao's stored value stays valid before
	// the operator regenerates and rewrites it (e.g. 720h for 30 days). 0
	// means generate once and never rotate. Rotation is not exact: the
	// operator reconciles periodically, so a value may rotate up to ~5m past
	// this deadline.
	// +kubebuilder:validation:Optional
	RotationPeriod metav1.Duration `json:"rotationPeriod,omitempty"`

	// Generator controls how the random value is produced.
	// +kubebuilder:validation:Optional
	Generator OpenBaoSecretGenerator `json:"generator,omitempty"`
}

// OpenBaoSecretGenerator configures random-value generation.
type OpenBaoSecretGenerator struct {
	// Key is the secret key under which the generated value is stored in
	// bao (and therefore in the VSO-materialized Kubernetes Secret).
	// Defaults to "value".
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="value"
	Key string `json:"key,omitempty"`

	// Length is the length of the generated value, excluding Prefix.
	// Defaults to 24. Must be between 1 and 1024.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=24
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1024
	Length int `json:"length,omitempty"`

	// Charset selects the character pool. One of: alphaNumSpecial (default:
	// lower+upper+digits+symbols), alphaNum, alpha, lower, upper, numeric,
	// hex.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=alphaNumSpecial;alphaNum;alpha;lower;upper;numeric;hex
	Charset string `json:"charset,omitempty"`

	// Prefix is a literal string prepended to the generated value (e.g.
	// "$2b$"). Excluded from Length. Rarely needed.
	// +kubebuilder:validation:Optional
	Prefix string `json:"prefix,omitempty"`
}

// OpenBaoGeneratedSecretStatus defines the observed state.
type OpenBaoGeneratedSecretStatus struct {
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

	// LastWrittenMount captures the KVv2 mount the controller last wrote
	// into, for rename cleanup across a simultaneous path + mount edit.
	// +optional
	LastWrittenMount string `json:"lastWrittenMount,omitempty"`

	// LastRotation is when the value was last generated and written. 0 means
	// never generated yet.
	// +optional
	LastRotation metav1.Time `json:"lastRotation,omitempty"`

	// LastRequestedRotation is the last on-demand rotation token (value of
	// the RotationAnnotationKey annotation) this controller has processed,
	// so a repeated annotation value does not rotate again. Empty means no
	// on-demand rotation has been processed yet.
	// +optional
	LastRequestedRotation string `json:"lastRequestedRotation,omitempty"`

	// Version is bao's KVv2 version of the last written value.
	// +optional
	Version int `json:"version,omitempty"`
}

// BaoName returns the KV path (the identity within the mount).
func (d *OpenBaoGeneratedSecret) BaoName() string {
	raw := d.Spec.Path
	if raw == "" {
		raw = d.Name
	}
	return strings.Trim(raw, "/")
}

// OpenBaoNamespace returns the bao namespace this CR's API calls target.
func (d *OpenBaoGeneratedSecret) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

// KVMount resolves the KVv2 mount, defaulting to "secret".
func (d *OpenBaoGeneratedSecret) KVMount() string {
	if strings.TrimSpace(d.Spec.Mount) == "" {
		return "secret"
	}
	return strings.Trim(d.Spec.Mount, "/")
}

// GetPath returns the synthetic identifier used in collision messages/logs.
func (d *OpenBaoGeneratedSecret) GetPath() string {
	return d.KVMount() + "/data/" + d.BaoName()
}

// GetPayload is unused by the drift comparator.
func (d *OpenBaoGeneratedSecret) GetPayload() map[string]interface{} {
	return nil
}

// RotationRequested reports whether a pending on-demand rotation has been
// requested via the RotationAnnotationKey annotation that this controller
// has not yet processed. Empty or already-processed tokens are ignored.
func (d *OpenBaoGeneratedSecret) RotationRequested() bool {
	token := strings.TrimSpace(d.Annotations[RotationAnnotationKey])
	if token == "" {
		return false
	}
	return token != d.Status.LastRequestedRotation
}

// IsEquivalentToDesiredState reports whether the stored value is still fresh.
// Fresh = generated at least once and (when rotating) LastRotation + the
// rotation period is still in the future and there is no pending on-demand
// rotation request. The bao payload is not consulted — the decision is purely
// schedule + request driven.
func (d *OpenBaoGeneratedSecret) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	if d.RotationRequested() {
		return false // on-demand rotation -> write path
	}
	if d.Status.LastRotation.IsZero() {
		return false // never written -> create path
	}
	if d.Spec.RotationPeriod.Duration <= 0 {
		return true // generate once, no rotation; already written
	}
	return time.Now().Before(d.Status.LastRotation.Add(d.Spec.RotationPeriod.Duration))
}

func (d *OpenBaoGeneratedSecret) IsInitialized() bool { return true }

// IsDeletable is the data-kind reading: only an explicit deletionPolicy
// "Delete" removes the secret on CR deletion.
func (d *OpenBaoGeneratedSecret) IsDeletable() bool {
	return d.Spec.DeletionPolicy.DeletesDataKind()
}

func (d *OpenBaoGeneratedSecret) PrepareInternalValues(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoGeneratedSecret) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

// IsValid enforces spec-level invariants the CRD markers can't express.
func (d *OpenBaoGeneratedSecret) IsValid() (bool, error) {
	if strings.TrimSpace(d.Spec.Path) == "" {
		return false, fmt.Errorf("spec.path must not be empty")
	}
	if strings.TrimSpace(d.Spec.Mount) == "" {
		return false, fmt.Errorf("spec.mount must not be empty")
	}
	if strings.HasPrefix(strings.Trim(d.Spec.Path, "/"), "data/") {
		return false, fmt.Errorf("spec.path must not begin with %q (reserved for KVv2 metadata)", "data/")
	}
	if d.Spec.Generator.Length < 0 || d.Spec.Generator.Length > 1024 {
		return false, fmt.Errorf("spec.generator.length must be between 1 and 1024")
	}
	if d.Spec.RotationPeriod.Duration < 0 {
		return false, fmt.Errorf("spec.rotationPeriod must not be negative")
	}
	if c := d.Spec.Generator.Charset; c != "" && !knownCharset(c) {
		return false, fmt.Errorf("spec.generator.charset %q is not supported (alphaNumSpecial, alphaNum, alpha, lower, upper, numeric, hex)", c)
	}
	return true, nil
}

// Key returns the bao/K8s secret key for the generated value.
func (d *OpenBaoGeneratedSecret) Key() string {
	if strings.TrimSpace(d.Spec.Generator.Key) == "" {
		return "value"
	}
	return d.Spec.Generator.Key
}

// Length returns the resolved value length (default 24).
func (d *OpenBaoGeneratedSecret) Length() int {
	if d.Spec.Generator.Length <= 0 {
		return 24
	}
	return d.Spec.Generator.Length
}

// RotationInterval returns the configured rotation period (0 = no rotation).
func (d *OpenBaoGeneratedSecret) RotationInterval() time.Duration {
	return d.Spec.RotationPeriod.Duration
}

func knownCharset(c string) bool {
	switch c {
	case CharsetAlphaNumSpecial, CharsetAlphaNum, CharsetAlpha,
		CharsetNumeric, CharsetHex, CharsetLower, CharsetUpper:
		return true
	}
	return false
}

// charsetPool returns the character pool for the configured charset.
func (d *OpenBaoGeneratedSecret) charsetPool() string {
	switch d.Spec.Generator.Charset {
	case CharsetAlphaNum:
		return genLower + genUpper + genDigits
	case CharsetAlpha:
		return genLower + genUpper
	case CharsetNumeric:
		return genDigits
	case CharsetHex:
		return genDigits[:10] + "abcdef"
	case CharsetLower:
		return genLower
	case CharsetUpper:
		return genUpper
	default: // alphaNumSpecial (and empty)
		return genLower + genUpper + genDigits + genSymbols
	}
}

// Generate produces a cryptographically random value per the generator spec.
// The prefix is prepended and excluded from Length. Uses crypto/rand.Int to
// avoid modulo bias in the per-byte pool selection.
func (d *OpenBaoGeneratedSecret) Generate() (string, error) {
	pool := d.charsetPool()
	mod := big.NewInt(int64(len(pool)))
	length := d.Length()
	var sb strings.Builder
	sb.Grow(length + len(d.Spec.Generator.Prefix))
	sb.WriteString(d.Spec.Generator.Prefix)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, mod)
		if err != nil {
			return "", fmt.Errorf("%w: generating random value: %v", ErrGenerate, err)
		}
		sb.WriteByte(pool[n.Int64()])
	}
	return sb.String(), nil
}

// ErrGenerate wraps crypto/rand failures during value generation.
var ErrGenerate = errors.New("openbao secret generation")

func (d *OpenBaoGeneratedSecret) GetConditions() []metav1.Condition {
	return d.Status.Conditions
}

func (d *OpenBaoGeneratedSecret) SetConditions(conditions []metav1.Condition) {
	d.Status.Conditions = conditions
}

func (d *OpenBaoGeneratedSecret) IsBaoWritten() bool { return d.Status.BaoWritten }
func (d *OpenBaoGeneratedSecret) MarkBaoWritten()    { d.Status.BaoWritten = true }

func (d *OpenBaoGeneratedSecret) LastWrittenBaoName() string {
	return d.Status.LastWrittenBaoName
}

func (d *OpenBaoGeneratedSecret) LastWrittenOpenBaoNamespace() string {
	return d.Status.LastWrittenOpenBaoNamespace
}

func (d *OpenBaoGeneratedSecret) SetLastWrittenBaoIdentity(name, namespace string) {
	d.Status.LastWrittenBaoName = name
	d.Status.LastWrittenOpenBaoNamespace = namespace
}

// MarkWritten records the mount, KVv2 version and rotation time on a
// successful (re)generation.
func (d *OpenBaoGeneratedSecret) MarkWritten(mount string, version int, rotatedAt time.Time) {
	d.Status.LastWrittenMount = mount
	d.Status.Version = version
	d.Status.LastRotation = metav1.NewTime(rotatedAt.UTC())
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obgen
// +kubebuilder:printcolumn:name="Mount",type=string,JSONPath=`.spec.mount`
// +kubebuilder:printcolumn:name="Path",type=string,JSONPath=`.spec.path`
// +kubebuilder:printcolumn:name="Rotation",type=string,JSONPath=`.spec.rotationPeriod`
// +kubebuilder:printcolumn:name="Version",type=integer,JSONPath=`.status.version`

// OpenBaoGeneratedSecret is the Schema for the openbaogeneratedsecrets API.
type OpenBaoGeneratedSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoGeneratedSecretSpec   `json:"spec,omitempty"`
	Status OpenBaoGeneratedSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoGeneratedSecretList contains a list of OpenBaoGeneratedSecret.
type OpenBaoGeneratedSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoGeneratedSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoGeneratedSecret{}, &OpenBaoGeneratedSecretList{})
}
