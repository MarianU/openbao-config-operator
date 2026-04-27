// Package vaultobject defines the contract that primitive CRDs implement
// to be reconciled against OpenBao.
//
// Package-default: deepcopy OFF. Each struct that needs deepcopy carries
// its own +kubebuilder:object:generate=true marker.
//
// +kubebuilder:object:generate=false
package vaultobject
