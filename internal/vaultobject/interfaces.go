package vaultobject

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// VaultObject is the contract every primitive CRD implements so the shared
// reconciler can drive it: where to write on the bao server, what to write,
// when the current state already matches, and what spec-level rejection
// looks like.
//
// PrepareInternalValues and PrepareTLSConfig are required even though Policy
// (the first primitive) implements them as no-ops. They are kept on the
// core interface — instead of behind an opt-in Preparer extension — because
// upcoming primitives need them: KubernetesAuthEngineRole resolves auth
// accessors via list-mounts before write, PKISecretEngine writes a TLS
// config block, GroupAlias resolves the parent Group's canonical id. Two
// no-op methods are cheaper than per-primitive type assertions in the
// shared reconcile loop, and the no-ops document where future implementers
// hook in.
type VaultObject interface {
	GetPath() string
	GetPayload() map[string]any
	// IsEquivalentToDesiredState returns true when the passed current-state
	// payload matches the desired state GetPayload() would emit.
	IsEquivalentToDesiredState(payload map[string]any) bool
	IsInitialized() bool
	IsValid() (bool, error)
	IsDeletable() bool
	PrepareInternalValues(ctx context.Context, obj client.Object) error
	PrepareTLSConfig(ctx context.Context, obj client.Object) error
}

// ConditionsAware is implemented by any CRD whose Status carries
// metav1.Condition entries.
type ConditionsAware interface {
	GetConditions() []metav1.Condition
	SetConditions(conditions []metav1.Condition)
}

// WriteTracker is implemented by any CRD that needs durable cross-reconcile
// state about whether it has ever successfully written to OpenBao.
//
// The shared reconciler uses it on the deletion path: a CR that never wrote
// to bao must NOT call BaoDelete (would strand the CR in Terminating on
// primitives with strict delete endpoints), but a CR that wrote and then
// flipped Ready=True→False (token lost capability, etc.) MUST call
// BaoDelete or it leaks server-side state. The condition history is
// transient (apiserver may compact, restore from backup loses it) and so
// not load-bearing for cleanup correctness; this status field is.
type WriteTracker interface {
	IsBaoWritten() bool
	MarkBaoWritten()
}
