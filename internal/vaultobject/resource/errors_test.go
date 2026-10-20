package resource

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"strings"
	"testing"

	baoclient "github.com/stakater/openbao-config-operator/internal/client"
)

// status returns a *baoclient.StatusError mimicking what the wrapper at
// internal/client/bao_client.go produces for SDK errors with an HTTP code.
func status(code int, msg string) error {
	return &baoclient.StatusError{StatusCode: code, Inner: errors.New(msg)}
}

// classifyErrCases is the single description of what ClassifyErr does. It is
// package-level so TestEveryReasonIsReachable can ask whether it covers every
// declared Reason constant without maintaining a second list that could drift.
var classifyErrCases = []struct {
	name string
	in   error
	want string
}{
	{"nil", nil, ReasonReconciled},

	// Status-driven cases: classification comes from StatusCode, not text.
	{"403-permission-denied", status(http.StatusForbidden, "permission denied"), ReasonForbidden},
	{"403-empty-message", status(http.StatusForbidden, ""), ReasonForbidden},
	{"404-clean", status(http.StatusNotFound, "not found"), ReasonNotFound},
	{"404-empty-message", status(http.StatusNotFound, ""), ReasonNotFound},
	{"500-with-not-found-text", status(http.StatusInternalServerError, "upstream service not found"), ReasonBaoError},
	{"500-with-forbidden-text", status(http.StatusInternalServerError, "auth backend reports permission denied"), ReasonBaoError},
	{"503", status(http.StatusServiceUnavailable, "service unavailable"), ReasonBaoError},
	{"400", status(http.StatusBadRequest, "bad request"), ReasonBaoError},

	// Non-StatusError errors (network layer, context, etc.) → BaoError —
	// we no longer guess from message text.
	{"dial-error", errors.New("dial tcp 127.0.0.1:8200: connection refused"), ReasonBaoError},
	{"context-cancelled", errors.New("context canceled"), ReasonBaoError},
	{"empty-message", errors.New(""), ReasonBaoError},
	{"plain-not-found-text", errors.New("not found"), ReasonBaoError},
	{"plain-403-text", errors.New("status 403"), ReasonBaoError},

	// Not-found sentinels. Every wrapper Get coalesces a 404 (and bao's 400
	// "no default issuer") into a bare sentinel before the error leaves
	// internal/client, so these — not the synthetic 404 above — are the shape
	// production actually produces.
	{"baoclient-sentinel", baoclient.ErrNotFound, ReasonNotFound},
	{"reconciler-sentinel", ErrBaoNotFound, ReasonNotFound},
	{"sentinel-through-BaoOpErr", BaoOpErr("reading CA", "pki-int", baoclient.ErrNotFound), ReasonNotFound},
	{"sentinel-through-plain-wrap", fmt.Errorf("outer: %w", baoclient.ErrNotFound), ReasonNotFound},

	// Sentinel-driven cases, so the table covers every reason ClassifyErr
	// can produce (see TestEveryReasonIsReachable).
	{"name-collision", fmt.Errorf("%w: owned by ns-a/editor", ErrNameCollision), ReasonNameCollision},
	{"invalid-spec", fmt.Errorf("%w: type is immutable", ErrInvalidSpec), ReasonInvalid},
	{"delete-blocked", fmt.Errorf("%w: deletion_allowed=false", ErrDeleteBlocked), ReasonDeleteBlocked},
	{"internal", fmt.Errorf("%w: listing peers", ErrInternal), ReasonInternalError},
	{"awaiting-signature", fmt.Errorf("%w: sign the CSR", ErrAwaitingExternalSignature), ReasonAwaitingExternalSignature},

	// Precedence: a more specific sentinel wins over the not-found check.
	// A post-create immutability violation discovered during a read that also
	// reports not-found must surface as Invalid, not NotFound.
	{"invalid-spec-beats-not-found",
		fmt.Errorf("%w: %v", ErrInvalidSpec, baoclient.ErrNotFound), ReasonInvalid},
	{"awaiting-signature-beats-not-found",
		fmt.Errorf("%w: %w", ErrAwaitingExternalSignature, baoclient.ErrNotFound), ReasonAwaitingExternalSignature},
}

func TestClassifyErr(t *testing.T) {
	t.Parallel()
	for _, tc := range classifyErrCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyErr(tc.in); got != tc.want {
				t.Errorf("ClassifyErr(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// BaoOpErr must add context without breaking the two things the base relies
// on: errors.Is for the create-path check, and errors.As for HTTP status
// classification. A %v in place of the %w silently breaks both.
func TestBaoOpErrPreservesWrapping(t *testing.T) {
	t.Parallel()

	wrapped := BaoOpErr("reading CA serial after set-signed", "pki-team-a-int", baoclient.ErrNotFound)
	if !errors.Is(wrapped, baoclient.ErrNotFound) {
		t.Error("errors.Is lost baoclient.ErrNotFound through BaoOpErr")
	}
	if !strings.Contains(wrapped.Error(), "reading CA serial after set-signed") {
		t.Errorf("message dropped the operation: %q", wrapped.Error())
	}
	if !strings.Contains(wrapped.Error(), `"pki-team-a-int"`) {
		t.Errorf("message dropped the quoted target: %q", wrapped.Error())
	}

	// The base's create-path check is errors.Is against ErrBaoNotFound; a
	// BaoGet that wraps its sentinel must still route to BaoWrite.
	if !errors.Is(BaoOpErr("reading policy", "editor", ErrBaoNotFound), ErrBaoNotFound) {
		t.Error("errors.Is lost ErrBaoNotFound through BaoOpErr — create path would break")
	}

	// errors.As must still reach the status for non-sentinel failures.
	var se *baoclient.StatusError
	if !errors.As(BaoOpErr("writing policy", "editor", status(http.StatusForbidden, "denied")), &se) {
		t.Fatal("errors.As lost *StatusError through BaoOpErr")
	}
	if se.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want %d", se.StatusCode, http.StatusForbidden)
	}
}

// Every declared Reason constant must be emittable. Enumerating declarations
// from the AST — rather than hand-listing them — is what makes a newly-added
// constant fail this test instead of quietly joining it.
//
// Narrow by design: this proves reachability through ClassifyErr, not that a
// real bao failure reaches it. The baoclient-sentinel case in classifyErrCases
// is what pins the shape production actually produces.
func TestEveryReasonIsReachable(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "errors.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing errors.go: %v", err)
	}

	declared := map[string]string{} // const name -> string value
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range vs.Names {
			if !strings.HasPrefix(name.Name, "Reason") || i >= len(vs.Values) {
				continue
			}
			if lit, ok := vs.Values[i].(*ast.BasicLit); ok {
				declared[name.Name] = strings.Trim(lit.Value, `"`)
			}
		}
		return true
	})
	if len(declared) == 0 {
		t.Fatal("parsed no Reason constants from errors.go — did the file or const block move?")
	}

	// Reasons the base writes directly rather than via ClassifyErr. Adding an
	// entry is a deliberate act; the point is that it cannot be skipped.
	emittedElsewhere := map[string]string{}

	produced := map[string]bool{}
	for _, tc := range classifyErrCases {
		produced[ClassifyErr(tc.in)] = true
	}

	for name, value := range declared {
		if produced[value] || emittedElsewhere[name] != "" {
			continue
		}
		t.Errorf("Reason constant %s (%q) is unreachable: no case in classifyErrCases "+
			"produces it and it is not declared in emittedElsewhere", name, value)
	}
}

func TestClassifyErr_NameCollision(t *testing.T) {
	t.Parallel()
	wrapped := fmt.Errorf("%w: bao policy %q already owned by Policy %s/%s",
		ErrNameCollision, "editor", "ns-b", "editor")
	if got := ClassifyErr(wrapped); got != ReasonNameCollision {
		t.Errorf("ClassifyErr(wrapped ErrNameCollision) = %q, want %q", got, ReasonNameCollision)
	}
	// A bare error with similar text but no sentinel wrap must NOT be
	// classified as a collision — keeps the detection precise.
	plain := errors.New("name collision: bao policy editor")
	if got := ClassifyErr(plain); got == ReasonNameCollision {
		t.Errorf("plain error should not match ReasonNameCollision, got %q", got)
	}
}

// Wrapped StatusError still classifies correctly through fmt.Errorf("%w").
func TestClassifyErr_StatusErrorThroughWrap(t *testing.T) {
	t.Parallel()
	wrapped := fmt.Errorf("calling sys/auth: %w", status(http.StatusForbidden, "permission denied"))
	if got := ClassifyErr(wrapped); got != ReasonForbidden {
		t.Errorf("ClassifyErr(wrapped 403) = %q, want %q", got, ReasonForbidden)
	}
}

func TestClassifyErr_InvalidSpec(t *testing.T) {
	t.Parallel()
	wrapped := fmt.Errorf("%w: type is immutable post-create", ErrInvalidSpec)
	if got := ClassifyErr(wrapped); got != ReasonInvalid {
		t.Errorf("ClassifyErr(wrapped ErrInvalidSpec) = %q, want %q", got, ReasonInvalid)
	}
	plain := errors.New("invalid spec: oops")
	if got := ClassifyErr(plain); got == ReasonInvalid {
		t.Errorf("plain error should not match ReasonInvalid, got %q", got)
	}
}

func TestClassifyErr_AwaitingExternalSignature(t *testing.T) {
	t.Parallel()
	wrapped := fmt.Errorf("%w: sign the CSR in secret %q", ErrAwaitingExternalSignature, "x-intermediate-csr")
	if got := ClassifyErr(wrapped); got != ReasonAwaitingExternalSignature {
		t.Errorf("ClassifyErr(wrapped ErrAwaitingExternalSignature) = %q, want %q", got, ReasonAwaitingExternalSignature)
	}
	// A bare error with similar text but no sentinel wrap must NOT classify
	// as awaiting — keeps detection precise.
	plain := errors.New("awaiting external signature for some reason")
	if got := ClassifyErr(plain); got == ReasonAwaitingExternalSignature {
		t.Errorf("plain error should not match ReasonAwaitingExternalSignature, got %q", got)
	}
}

func TestClassifyErr_DeleteBlocked(t *testing.T) {
	t.Parallel()
	wrapped := fmt.Errorf("%w: bao requires deletion_allowed=true", ErrDeleteBlocked)
	if got := ClassifyErr(wrapped); got != ReasonDeleteBlocked {
		t.Errorf("ClassifyErr(wrapped ErrDeleteBlocked) = %q, want %q", got, ReasonDeleteBlocked)
	}
	// A bare 400 from bao must NOT classify as DeleteBlocked — only the
	// sentinel wrap routes there. Without this guard, every "bad request"
	// from bao would shadow real DeleteBlocked situations.
	plain := status(http.StatusBadRequest, "deletion is not allowed for key")
	if got := ClassifyErr(plain); got == ReasonDeleteBlocked {
		t.Errorf("bare 400 should not match ReasonDeleteBlocked, got %q", got)
	}
}
