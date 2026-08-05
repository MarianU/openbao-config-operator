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
// PrepareInternalValues and PrepareTLSConfig are on the core interface —
// rather than behind an opt-in extension — so the shared reconcile
// loop can call them unconditionally. Primitives that need to resolve
// server-dependent values before write (auth-mount accessor lookups,
// label-selector → namespace expansion, secret-ref dereferencing,
// per-mount TLS config) implement them with real logic; primitives
// that don't return nil. Two no-op methods are cheaper than per-call
// type assertions in the shared loop.
type VaultObject interface {
	GetPath() string
	GetPayload() map[string]any
	// IsEquivalentToDesiredState returns true when the passed current-state
	// payload matches the desired state GetPayload() would emit.
	IsEquivalentToDesiredState(payload map[string]any) bool
	IsInitialized() bool
	IsValid() (bool, error)
	// IsDeletable reports whether the bao object should be removed on
	// CR deletion (BaoDelete) or rename (BaoDeleteIdentity). False =
	// intentional orphan: finalizer released without touching bao,
	// logged + BaoObjectOrphaned Event. Implementations are hardcoded
	// constants (PKI CA, transit key) or reads of the mutable
	// spec.deletionPolicy. Re-evaluated every pass, including while
	// Terminating (flipping the policy releases a stuck delete) —
	// callers must never cache it or assume it constant per type.
	IsDeletable() bool
	PrepareInternalValues(ctx context.Context, obj client.Object) error
	PrepareTLSConfig(ctx context.Context, obj client.Object) error

	// BaoName returns the canonical name this CR writes to OpenBao.
	// Typically spec.name when set, otherwise metadata.name. Implementations
	// must lowercase / trim the same way the controller does on the wire so
	// the value round-trips through bao reads.
	BaoName() string

	// OpenBaoNamespace returns the bao namespace this CR's API calls target
	// (the value of the X-Vault-Namespace header). Empty string means the
	// root namespace.
	OpenBaoNamespace() string
}

// ConditionsAware is implemented by any CRD whose Status carries
// metav1.Condition entries.
type ConditionsAware interface {
	GetConditions() []metav1.Condition
	SetConditions(conditions []metav1.Condition)
}

// WriteTracker carries the durable signal that a bao object was
// confirmed under this CR's identity — set on every successful
// reconcile, written or adopted. The deletion path keys on it: a CR
// that never confirmed an object skips BaoDelete (avoids stranding in
// Terminating on strict delete endpoints); one that owned an object
// must still reach the deletion decision even after Ready flipped
// False, and an adopted orphan must still be tear-down-able under
// deletionPolicy=Delete. Condition history is transient (compaction,
// backup restore); this status field is the load-bearing record.
type WriteTracker interface {
	IsBaoWritten() bool
	MarkBaoWritten()
}

// RenameTracker is implemented by any CRD whose bao-side identity (name +
// openbao namespace) can change through spec edits. The shared reconciler
// records the identity it last successfully wrote, and when the next
// reconcile sees a different identity it deletes the previous bao object
// before writing the new one.
//
// Without this, a spec.name change creates a new bao object at the new
// identity and leaves the original orphaned — for ACL policies a security
// gap (a stale grant the operator no longer knows about), for mounts/auth
// methods a half-configured leftover.
//
// The identity tuple is (bao name, openbao namespace) because both are
// independently mutable: the user can rename the policy, move it to a
// different OpenBao namespace, or both in one edit.
type RenameTracker interface {
	LastWrittenBaoName() string
	LastWrittenOpenBaoNamespace() string
	SetLastWrittenBaoIdentity(name, namespace string)
}
