package v1alpha1

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicyNamePattern is a hand-maintained copy of the regex on spec.name's
// +kubebuilder:validation:Pattern marker; the source of truth is the marker
// on PolicySpec.Name in policy_types.go. The marker itself is exercised
// end-to-end against the apiserver in crd_validation_test.go (envtest), so
// production rejection of bad names is covered there. This unit-level
// regex test runs without envtest to document the anchoring intent and
// catch off-by-one mistakes during local iteration. Keep both copies in
// sync when changing the pattern.
const PolicyNamePattern = `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`

// Regression: OpenAPI v3 `pattern` does substring match by default, so an
// unanchored regex like `[a-z0-9]([-a-z0-9]*[a-z0-9])?` accepts "Bad_Name1"
// because the substring "a" matches. Anchoring with ^…$ is required.
func TestPolicy_NamePattern_AnchoredAndStrict(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(PolicyNamePattern)

	cases := []struct {
		in     string
		accept bool
	}{
		// valid bao policy names
		{"editor", true},
		{"team-a-editor", true},
		{"123abc", true},
		{"a", true},
		{"a-b", true},
		{"a1-b2-c3", true},

		// must be rejected
		{"Bad_Name1", false},      // mixed case + underscore
		{"editor!", false},        // special char
		{"_underscore", false},    // leading underscore
		{"-leading-dash", false},  // leading dash
		{"trailing-dash-", false}, // trailing dash
		{"UPPER", false},          // uppercase
		{"", false},               // empty
		{"a a", false},            // space
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := re.MatchString(c.in)
			if got != c.accept {
				t.Errorf("regex %q on %q: got=%v, want=%v", PolicyNamePattern, c.in, got, c.accept)
			}
		})
	}
}

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

// Regression: OpenBao normalizes whitespace on round-trip (notably trailing
// newlines). A naive reflect.DeepEqual on the policy body would flag every
// such CR as drifted on every periodic reconcile, causing a write-storm.
// The fix lives in IsEquivalentToDesiredState — strings.TrimSpace on both
// sides before comparing.
func TestPolicy_IsEquivalentToDesiredState_WhitespaceTolerant(t *testing.T) {
	t.Parallel()
	body := `path "secret/data/foo/*" { capabilities = ["read"] }`
	p := &Policy{}
	p.Spec.Policy = body

	cases := []struct {
		name   string
		stored string
		want   bool
	}{
		{"identical", body, true},
		{"trailing-newline-on-server", body + "\n", true},
		{"trailing-newlines-and-spaces", body + "\n  \n", true},
		{"leading-whitespace-on-server", "  \n" + body, true},
		{"leading-whitespace-on-spec", "  " + body, true}, // spec.policy normalized too
		{"semantic-difference", body + "; path \"x\" {}", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			specCR := &Policy{}
			specCR.Spec.Policy = body
			if tc.name == "leading-whitespace-on-spec" {
				specCR.Spec.Policy = "  " + body
			}
			got := specCR.IsEquivalentToDesiredState(map[string]any{"policy": tc.stored})
			if got != tc.want {
				t.Errorf("equivalent? got=%v want=%v\n  spec  : %q\n  stored: %q",
					got, tc.want, specCR.Spec.Policy, tc.stored)
			}
		})
	}
}

func TestPolicy_IsInitialized_IsDeletable(t *testing.T) {
	t.Parallel()
	p := &Policy{}
	if !p.IsInitialized() {
		t.Error("IsInitialized should always return true")
	}
	if !p.IsDeletable() {
		t.Error("IsDeletable should always return true")
	}
}

func TestPolicy_IsValid_AcceptsCleanBody(t *testing.T) {
	t.Parallel()
	p := &Policy{}
	p.Spec.Policy = `path "secret/*" { capabilities = ["read"] }`
	ok, err := p.IsValid()
	if !ok || err != nil {
		t.Errorf("IsValid should accept a clean body; got (%v, %v)", ok, err)
	}
}

// Defense in depth: the CRD's MinLength=1 marker already rejects empty
// spec.policy at admission, but a stale CRD or a unit-test bypass can let
// one through. IsValid must catch it — otherwise BaoGet's empty-body =
// missing assumption would loop forever (every reconcile creates an empty
// policy, next read returns "", classified as missing again).
func TestPolicy_IsValid_RejectsEmptyPolicy(t *testing.T) {
	t.Parallel()
	for _, body := range []string{"", "   ", "\n\t\n"} {
		p := &Policy{}
		p.Spec.Policy = body
		ok, err := p.IsValid()
		if ok {
			t.Errorf("IsValid should reject empty/whitespace-only spec.policy %q", body)
		}
		if err == nil || !strings.Contains(err.Error(), "must not be empty") {
			t.Errorf("error should explain the rejection; got %v", err)
		}
	}
}

// IsValid owns VCO-mount-placeholder rejection: a spec-level problem
// belongs in spec validation so the base stops requeueing and the user
// sees a stable error in CR status. The deny rule narrows on the
// "${<mount>/" shape — the trailing slash after a mount name is what
// distinguishes these from bao's own ACL templating which uses dotted
// paths (${identity.entity.name}, {{identity.entity.id}}).
func TestPolicy_IsValid_RejectsVCOPlaceholders(t *testing.T) {
	t.Parallel()
	bodies := []string{
		`path "secret/*" { allowed_parameters = { "accessor" = ["${auth/kubernetes/@accessor}"] } }`,
		`path "identity/group/${identity/group/team-a/@id}/*" { capabilities = ["read"] }`,
		`path "pki_int/issue/${pki/leaf/@role}" { capabilities = ["update"] }`,
	}
	for _, body := range bodies {
		t.Run(body[:40]+"...", func(t *testing.T) {
			p := &Policy{}
			p.Spec.Policy = body
			ok, err := p.IsValid()
			if ok {
				t.Fatal("IsValid should reject VCO-mount placeholders")
			}
			if err == nil {
				t.Fatal("IsValid should return a non-nil error explaining why")
			}
			msg := err.Error()
			for _, want := range []string{"placeholder", "bao auth list"} {
				if !strings.Contains(msg, want) {
					t.Errorf("error message must contain user-facing hint %q; got: %v", want, err)
				}
			}
			for _, leak := range []string{"Story 6", "VCO", "story 6"} {
				if strings.Contains(msg, leak) {
					t.Errorf("error message leaks internal jargon %q; got: %v", leak, err)
				}
			}
		})
	}
}

// Bao's own ACL templating uses dotted paths like ${identity.entity.name}
// and {{identity.entity.id}} — the bao server resolves these at policy
// evaluation. They must pass IsValid; only VCO-mount-shape placeholders
// (with a trailing slash after the mount name) are rejected.
func TestPolicy_IsValid_AcceptsBaoTemplating(t *testing.T) {
	t.Parallel()
	bodies := []string{
		// Dollar-brace dotted: bao's own templating shape.
		`path "secret/data/teams/${identity.entity.metadata.team}/*" { capabilities = ["read"] }`,
		`path "secret/data/${identity.entity.name}/*" { capabilities = ["read"] }`,
		// Double-brace: bao's other templating shape.
		`path "secret/data/{{identity.entity.id}}/*" { capabilities = ["read"] }`,
		// No interpolation at all.
		`path "secret/*" { capabilities = ["read"] }`,
	}
	for _, body := range bodies {
		t.Run(body[:40]+"...", func(t *testing.T) {
			p := &Policy{}
			p.Spec.Policy = body
			ok, err := p.IsValid()
			require.True(t, ok, "IsValid must accept bao's own templating; got err: %v", err)
			require.NoError(t, err)
		})
	}
}

func TestPolicy_PrepareInternalValues_NoOp(t *testing.T) {
	t.Parallel()
	p := &Policy{}
	p.Spec.Policy = `path "secret/*" { allowed_parameters = { "accessor" = ["${auth/kubernetes/@accessor}"] } }`
	// PrepareInternalValues used to gate accessor-templating; that check now
	// lives in IsValid. PrepareInternalValues must be a no-op so the base
	// doesn't double-reject (and waste reconciles requeueing).
	if err := p.PrepareInternalValues(context.Background(), p); err != nil {
		t.Errorf("PrepareInternalValues should be a no-op; got: %v", err)
	}
}

func TestPolicy_GetConditions_SetConditions_RoundTrip(t *testing.T) {
	t.Parallel()
	p := &Policy{}
	require.Nil(t, p.GetConditions(), "initial conditions should be nil")

	want := []metav1.Condition{
		{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"},
	}
	p.SetConditions(want)
	require.Equal(t, want, p.GetConditions())
}
