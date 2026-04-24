package vaultobject

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// VaultObject is implemented by every VCO-origin primitive CRD under
// api/vco/v1alpha1/. The contract mirrors redhat-cop/vault-config-operator's
// utils.VaultObject upstream, with two differences:
//   - GetKubeAuthConfiguration and GetVaultConnection always return nil in
//     our operator; the corresponding spec fields are stripped on copy and
//     the shared reconcile base uses the operator-global token from
//     OpenBaoExtension.
//   - No hashicorp/vault/api dependency.
type VaultObject interface {
	GetPath() string
	GetPayload() map[string]any
	// IsEquivalentToDesiredState returns true when the passed current-state
	// payload matches the desired state GetPayload() would emit. Engine
	// objects compare the tune payload via this method.
	IsEquivalentToDesiredState(payload map[string]any) bool
	IsInitialized() bool
	IsValid() (bool, error)
	IsDeletable() bool
	PrepareInternalValues(ctx context.Context, obj client.Object) error
	PrepareTLSConfig(ctx context.Context, obj client.Object) error
	GetKubeAuthConfiguration() *KubeAuthConfiguration
	GetVaultConnection() *VaultConnection
}

// VaultEngineObject is implemented by primitives that represent a secret
// engine mount (SecretEngineMount in Story 3 and its subtypes).
type VaultEngineObject interface {
	GetEngineListPath() string
	GetEngineTunePath() string
	GetTunePayload() map[string]any
	SetAccessor(accessor string)
}

// VaultPKIEngineObject is implemented by PKI primitives (Story 4).
// CreateExported takes our local SecretResponse adapter rather than
// hashicorp/vault/api's *Secret — we do not depend on that package.
type VaultPKIEngineObject interface {
	GetGeneratePath() string
	GetDeletePath() string
	GetGeneratedStatus() bool
	SetGeneratedStatus(status bool)
	GetConfigUrlsPath() string
	GetConfigCrlPath() string
	GetConfigUrlsPayload() map[string]any
	GetConfigCrlPayload() map[string]any
	CreateExported(ctx context.Context, secret *SecretResponse) (bool, error)
	SetExportedStatus(status bool)
	SetIntermediate(ctx context.Context) error
	GetSignedStatus() bool
	SetSignedStatus(status bool)
}

// ConditionsAware is implemented by any CRD whose Status carries
// metav1.Condition entries. All 11 VCO-origin primitives implement it.
type ConditionsAware interface {
	GetConditions() []metav1.Condition
	SetConditions(conditions []metav1.Condition)
}

// SecretResponse is our local adapter type replacing hashicorp/vault/api's
// *Secret in the VaultPKIEngineObject contract. Story 4 (PKI) populates
// the fields it actually consumes; Story 1 defines only the shell.
//
// Skipped from deepcopy generation: it is a transient request/response
// carrier, not embedded in any CR spec, and Data's interface{} values
// cannot be generically deep-copied.
//
// +kubebuilder:object:generate=false
type SecretResponse struct {
	Data map[string]any
}
