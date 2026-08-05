package v1alpha1

// DeletionPolicy decides what happens to the bao-side object when its
// CR is deleted or its bao identity is renamed: Retain releases the CR
// and intentionally orphans the bao object (re-applying an identical
// CR adopts it back), Delete removes it. Kinds default differently and
// read the field through the two helpers below so the fail-safe
// direction is explicit at the call site. The enforced registry of
// kind→group is TestDeletionPolicy_CRDMarkers. Printer columns exist
// on the data-bearing kinds only — that is where blast radius is
// checked before a teardown.
//
// +kubebuilder:validation:Enum=Retain;Delete
type DeletionPolicy string

const (
	DeletionPolicyRetain DeletionPolicy = "Retain"
	DeletionPolicyDelete DeletionPolicy = "Delete"
)

// DeletesDataKind is the reading for data-bearing kinds (mounts,
// namespaces): only an explicit Delete enables removal — empty (stale
// CRD, pruned manifest) means Retain, so destruction never depends on
// API-server defaulting.
func (p DeletionPolicy) DeletesDataKind() bool { return p == DeletionPolicyDelete }

// DeletesGrantKind is the reading for grant kinds (policies, roles,
// groups, aliases): only an explicit Retain disables removal — empty
// means Delete, so revocation never silently stops.
func (p DeletionPolicy) DeletesGrantKind() bool { return p != DeletionPolicyRetain }
