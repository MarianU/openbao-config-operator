package v1alpha1

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OpenBaoPolicyNamePattern is a hand-maintained copy of the regex on
// spec.name's +kubebuilder:validation:Pattern marker; the source of truth
// is the marker on OpenBaoPolicySpec.Name in openbaopolicy_types.go. The
// marker itself is exercised end-to-end against the apiserver in the
// openbaopolicy controller's crd_validation_test.go (envtest), so production
// rejection of bad names is covered there. This unit-level regex test runs
// without envtest to document the anchoring intent and catch off-by-one
// mistakes during local iteration. Keep both copies in sync when changing
// the pattern.
const OpenBaoPolicyNamePattern = `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`

// OpenBaoNamespacePattern mirrors the marker on
// OpenBaoPolicySpec.OpenBaoNamespace. Allows empty (root), single-segment
// (e.g. "acme"), nested (e.g. "acme/sub"), and an optional trailing slash.
// Rejects whitespace, uppercase, and leading/trailing dashes.
const OpenBaoNamespacePattern = `^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`

// Regression: OpenAPI v3 `pattern` does substring match by default, so an
// unanchored regex like `[a-z0-9]([-a-z0-9]*[a-z0-9])?` accepts "Bad_Name1"
// because the substring "a" matches. Anchoring with ^…$ is required.
func TestOpenBaoPolicy_NamePattern_AnchoredAndStrict(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(OpenBaoPolicyNamePattern)

	cases := []struct {
		in     string
		accept bool
	}{
		{"editor", true},
		{"team-a-editor", true},
		{"123abc", true},
		{"a", true},
		{"a-b", true},
		{"a1-b2-c3", true},

		{"Bad_Name1", false},
		{"editor!", false},
		{"_underscore", false},
		{"-leading-dash", false},
		{"trailing-dash-", false},
		{"UPPER", false},
		{"", false},
		{"a a", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := re.MatchString(c.in)
			if got != c.accept {
				t.Errorf("regex %q on %q: got=%v, want=%v", OpenBaoPolicyNamePattern, c.in, got, c.accept)
			}
		})
	}
}

// OpenBaoNamespace pattern accepts empty, single-segment, nested, and
// trailing-slash forms. Rejects uppercase, whitespace, leading slash.
func TestOpenBaoPolicy_OpenBaoNamespacePattern(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(OpenBaoNamespacePattern)

	cases := []struct {
		in     string
		accept bool
	}{
		// valid
		{"", true},      // empty = root
		{"acme", true},  // single segment
		{"acme/", true}, // trailing slash
		{"a", true},     // minimal
		{"acme/sub", true},
		{"acme/sub/", true},
		{"team-a/dev/cluster-1", true},
		{"team-a/dev/cluster-1/", true},

		// invalid
		{"/acme", false},     // leading slash
		{"ACME", false},      // uppercase
		{"acme name", false}, // whitespace
		{"-leading", false},  // leading dash
		{"trailing-", false}, // trailing dash on segment
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := re.MatchString(c.in)
			if got != c.accept {
				t.Errorf("regex %q on %q: got=%v, want=%v", OpenBaoNamespacePattern, c.in, got, c.accept)
			}
		})
	}
}

func TestOpenBaoPolicy_BaoName(t *testing.T) {
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
			p := &OpenBaoPolicy{}
			p.Name = tc.metaName
			p.Spec.Name = tc.specName
			if got := p.BaoName(); got != tc.want {
				t.Errorf("BaoName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOpenBaoPolicy_OpenBaoNamespace_NormalizesWhitespace(t *testing.T) {
	t.Parallel()
	tests := []struct {
		spec, want string
	}{
		{"", ""},
		{"acme/", "acme/"},
		{"  acme/  ", "acme/"}, // spec-side whitespace trimmed
	}
	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			p := &OpenBaoPolicy{}
			p.Spec.OpenBaoNamespace = tc.spec
			require.Equal(t, tc.want, p.OpenBaoNamespace())
		})
	}
}

func TestOpenBaoPolicy_GetPath_DoesNotIncludeNamespace(t *testing.T) {
	t.Parallel()
	// X-Vault-Namespace scopes the call; the path stays relative to the
	// targeted namespace. This is the contract bao itself uses — namespace
	// in header, path relative to namespace — so GetPath must not embed
	// spec.openbaoNamespace into the URL.
	p := &OpenBaoPolicy{}
	p.Name = "secret-reader"
	p.Spec.OpenBaoNamespace = "acme/"
	if got, want := p.GetPath(), "sys/policies/acl/secret-reader"; got != want {
		t.Errorf("GetPath() = %q, want %q", got, want)
	}
}

func TestOpenBaoPolicy_GetPayload(t *testing.T) {
	t.Parallel()
	p := &OpenBaoPolicy{}
	p.Spec.Policy = `path "secret/*" { capabilities = ["read"] }`
	got := p.GetPayload()
	if got["policy"] != p.Spec.Policy {
		t.Errorf("GetPayload()[policy] = %v, want %q", got["policy"], p.Spec.Policy)
	}
}

func TestOpenBaoPolicy_IsEquivalentToDesiredState(t *testing.T) {
	t.Parallel()
	p := &OpenBaoPolicy{}
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
func TestOpenBaoPolicy_IsEquivalentToDesiredState_WhitespaceTolerant(t *testing.T) {
	t.Parallel()
	body := `path "secret/data/foo/*" { capabilities = ["read"] }`
	p := &OpenBaoPolicy{}
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
		{"leading-whitespace-on-spec", "  " + body, true},
		{"semantic-difference", body + "; path \"x\" {}", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			specCR := &OpenBaoPolicy{}
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

func TestOpenBaoPolicy_IsInitialized_IsDeletable(t *testing.T) {
	t.Parallel()
	p := &OpenBaoPolicy{}
	if !p.IsInitialized() {
		t.Error("IsInitialized should always return true")
	}
	if !p.IsDeletable() {
		t.Error("empty deletionPolicy on a grant kind must mean Delete")
	}
}

func TestOpenBaoPolicy_IsValid_AcceptsCleanBody(t *testing.T) {
	t.Parallel()
	p := &OpenBaoPolicy{}
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
func TestOpenBaoPolicy_IsValid_RejectsEmptyPolicy(t *testing.T) {
	t.Parallel()
	for _, body := range []string{"", "   ", "\n\t\n"} {
		p := &OpenBaoPolicy{}
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
func TestOpenBaoPolicy_IsValid_RejectsVCOPlaceholders(t *testing.T) {
	t.Parallel()
	bodies := []string{
		`path "secret/*" { allowed_parameters = { "accessor" = ["${auth/kubernetes/@accessor}"] } }`,
		`path "identity/group/${identity/group/team-a/@id}/*" { capabilities = ["read"] }`,
		`path "pki_int/issue/${pki/leaf/@role}" { capabilities = ["update"] }`,
	}
	for _, body := range bodies {
		t.Run(body[:40]+"...", func(t *testing.T) {
			p := &OpenBaoPolicy{}
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
func TestOpenBaoPolicy_IsValid_AcceptsBaoTemplating(t *testing.T) {
	t.Parallel()
	bodies := []string{
		`path "secret/data/teams/${identity.entity.metadata.team}/*" { capabilities = ["read"] }`,
		`path "secret/data/${identity.entity.name}/*" { capabilities = ["read"] }`,
		`path "secret/data/{{identity.entity.id}}/*" { capabilities = ["read"] }`,
		`path "secret/*" { capabilities = ["read"] }`,
	}
	for _, body := range bodies {
		t.Run(body[:40]+"...", func(t *testing.T) {
			p := &OpenBaoPolicy{}
			p.Spec.Policy = body
			ok, err := p.IsValid()
			require.True(t, ok, "IsValid must accept bao's own templating; got err: %v", err)
			require.NoError(t, err)
		})
	}
}

func TestOpenBaoPolicy_PrepareInternalValues_NoOp(t *testing.T) {
	t.Parallel()
	p := &OpenBaoPolicy{}
	p.Spec.Policy = `path "secret/*" { allowed_parameters = { "accessor" = ["${auth/kubernetes/@accessor}"] } }`
	if err := p.PrepareInternalValues(context.Background(), p); err != nil {
		t.Errorf("PrepareInternalValues should be a no-op; got: %v", err)
	}
}

func TestOpenBaoPolicy_GetConditions_SetConditions_RoundTrip(t *testing.T) {
	t.Parallel()
	p := &OpenBaoPolicy{}
	require.Nil(t, p.GetConditions(), "initial conditions should be nil")

	want := []metav1.Condition{
		{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"},
	}
	p.SetConditions(want)
	require.Equal(t, want, p.GetConditions())
}
