package v1alpha1

import (
	"testing"
)

func mkKvSecretRef() *OpenBaoKvSecret {
	return &OpenBaoKvSecret{
		Spec: OpenBaoKvSecretSpec{
			Mount:        "secret",
			Path:         "apps/settings",
			SourceSecret: "src",
		},
	}
}

func TestKvSecret_IsEquivalentToDesiredState_Reference(t *testing.T) {
	t.Parallel()
	d := mkKvSecretRef()

	// Equal: bao current == source desired -> no write.
	if !d.IsEquivalentToDesiredState(map[string]any{
		"data":    map[string]string{"a": "1"},
		"desired": map[string]string{"a": "1"},
	}) {
		t.Fatal("expected equivalent (no write) when bao matches source")
	}

	// Source has a new key -> write.
	if d.IsEquivalentToDesiredState(map[string]any{
		"data":    map[string]string{"a": "1"},
		"desired": map[string]string{"a": "1", "b": "2"},
	}) {
		t.Fatal("expected NOT equivalent (write) when source added a key")
	}

	// Source value changed -> write.
	if d.IsEquivalentToDesiredState(map[string]any{
		"data":    map[string]string{"a": "1"},
		"desired": map[string]string{"a": "9"},
	}) {
		t.Fatal("expected NOT equivalent (write) when source value changed")
	}
}

func TestKvSecret_IsEquivalentToDesiredState_EmptySemantics(t *testing.T) {
	t.Parallel()
	d := mkKvSecretRef()

	// Both empty (freshly-created empty anchor vs nothing in bao) -> equivalent.
	if !d.IsEquivalentToDesiredState(map[string]any{}) {
		t.Fatal("expected equivalent when both sides are empty")
	}
	// Source emptied but bao retains stale data -> NOT equivalent (write/delete).
	if d.IsEquivalentToDesiredState(map[string]any{
		"data": map[string]string{"old": "1"},
	}) {
		t.Fatal("expected NOT equivalent when source emptied but bao retains data")
	}
}

func TestKvSecret_IsValid_RequiresSource(t *testing.T) {
	t.Parallel()
	if ok, _ := (&OpenBaoKvSecret{Spec: OpenBaoKvSecretSpec{Path: "a", Mount: "secret"}}).IsValid(); ok {
		t.Fatal("spec without sourceSecret must be rejected")
	}
	if ok, _ := mkKvSecretRef().IsValid(); !ok {
		t.Fatal("complete reference-only spec must be valid")
	}
	if ok, _ := (&OpenBaoKvSecret{Spec: OpenBaoKvSecretSpec{Path: "data/bad", SourceSecret: "s"}}).IsValid(); ok {
		t.Fatal("data/-prefixed path must be rejected")
	}
}

func TestKvSecret_BaoNameDefaultsToMetaName(t *testing.T) {
	t.Parallel()
	d := mkKvSecretRef()
	d.Name = "my-secret"
	d.Spec.Path = ""
	if got := d.BaoName(); got != "my-secret" {
		t.Fatalf("BaoName with empty path = %q, want metadata.name", got)
	}
}
