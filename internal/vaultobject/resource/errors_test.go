package resource

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
)

// status returns a *baoclient.StatusError mimicking what the wrapper at
// internal/client/bao_client.go produces for SDK errors with an HTTP code.
func status(code int, msg string) error {
	return &baoclient.StatusError{StatusCode: code, Inner: errors.New(msg)}
}

func TestClassifyErr(t *testing.T) {
	t.Parallel()
	tests := []struct {
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
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyErr(tc.in); got != tc.want {
				t.Errorf("ClassifyErr(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
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
