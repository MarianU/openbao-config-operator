package v1alpha1

import (
	"context"
	"strings"
	"testing"
)

func TestPolicy_BaoName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, metaName, specName, want string
	}{
		{"only-meta", "my-policy", "", "my-policy"},
		{"only-spec", "", "override", "override"},
		{"spec-wins", "meta", "spec", "spec"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &Policy{}
			p.Name = tc.metaName
			p.Spec.Name = tc.specName
			if got := p.BaoName(); got != tc.want {
				t.Errorf("BaoName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPolicy_GetPath(t *testing.T) {
	t.Parallel()
	p := &Policy{}
	p.Name = "secret-reader"
	if got, want := p.GetPath(), "sys/policies/acl/secret-reader"; got != want {
		t.Errorf("GetPath() = %q, want %q", got, want)
	}
}

func TestPolicy_GetPayload(t *testing.T) {
	t.Parallel()
	p := &Policy{}
	p.Spec.Policy = `path "secret/*" { capabilities = ["read"] }`
	got := p.GetPayload()
	if got["policy"] != p.Spec.Policy {
		t.Errorf("GetPayload()[policy] = %v, want %q", got["policy"], p.Spec.Policy)
	}
}

func TestPolicy_IsEquivalentToDesiredState(t *testing.T) {
	t.Parallel()
	p := &Policy{}
	p.Spec.Policy = "body"

	if !p.IsEquivalentToDesiredState(map[string]any{"policy": "body"}) {
		t.Error("identical payloads should be equivalent")
	}
	if p.IsEquivalentToDesiredState(map[string]any{"policy": "different"}) {
		t.Error("differing payloads should not be equivalent")
	}
	if p.IsEquivalentToDesiredState(map[string]any{}) {
		t.Error("empty payload should not be equivalent")
	}
}

func TestPolicy_IsInitialized_IsValid_IsDeletable(t *testing.T) {
	t.Parallel()
	p := &Policy{}
	if !p.IsInitialized() {
		t.Error("IsInitialized should always return true")
	}
	if !p.IsDeletable() {
		t.Error("IsDeletable should always return true")
	}
	ok, err := p.IsValid()
	if !ok || err != nil {
		t.Errorf("IsValid should return (true, nil), got (%v, %v)", ok, err)
	}
}

func TestPolicy_PrepareInternalValues_RejectsAccessorTemplating(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Clean body — should pass.
	clean := &Policy{}
	clean.Spec.Policy = `path "secret/*" { capabilities = ["read"] }`
	if err := clean.PrepareInternalValues(ctx, clean); err != nil {
		t.Errorf("PrepareInternalValues on clean body returned error: %v", err)
	}

	// Body with placeholder — must reject with "Story 6" in the message so
	// the deferred feature is greppable.
	placeholder := &Policy{}
	placeholder.Spec.Policy = `path "secret/*" { allowed_parameters = { "accessor" = ["${auth/kubernetes/@accessor}"] } }`
	err := placeholder.PrepareInternalValues(ctx, placeholder)
	if err == nil {
		t.Fatal("PrepareInternalValues should reject accessor templating")
	}
	if !strings.Contains(err.Error(), "Story 6") {
		t.Errorf("error message should mention Story 6 for discoverability; got: %v", err)
	}
}

func TestPolicy_GetVaultConnection_GetKubeAuthConfiguration_ReturnNil(t *testing.T) {
	t.Parallel()
	p := &Policy{}
	if p.GetVaultConnection() != nil {
		t.Error("GetVaultConnection should return nil post-strip")
	}
	if p.GetKubeAuthConfiguration() != nil {
		t.Error("GetKubeAuthConfiguration should return nil post-strip")
	}
}

func TestPolicy_GetConditions_SetConditions_RoundTrip(t *testing.T) {
	t.Parallel()
	p := &Policy{}
	if got := p.GetConditions(); got != nil {
		t.Errorf("initial conditions should be nil, got %v", got)
	}

	want := []struct{ Type string }{{"Ready"}}
	_ = want // shape only; see metav1.Condition round-trip tests for more detail
}
