// Package vaultobject defines the interfaces and value types that
// VCO-origin primitive CRDs under api/vco/v1alpha1/ implement or reference.
// It mirrors the shape of redhat-cop/vault-config-operator's
// api/v1alpha1/utils package without importing hashicorp/vault/api.
//
// Story 1 only populates the surface required by the Policy primitive;
// later stories extend the package as their primitives are copied.
// See docs/plans/PLAN-vco-cherrypick-roadmap.md and
// docs/plans/PLAN-vco-st1-foundation-policy.md.
//
// Package-default: deepcopy OFF. Each struct that needs deepcopy carries
// its own +kubebuilder:object:generate=true marker. Interfaces and
// transient adapter types (e.g. SecretResponse) are intentionally skipped.
//
// +kubebuilder:object:generate=false
package vaultobject
