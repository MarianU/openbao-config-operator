package resource

import (
	"errors"
	"testing"
)

func TestClassifyErr(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   error
		want string
	}{
		{"nil", nil, ReasonReconciled},
		{"permission-denied", errors.New("bao PUT /v1/sys/policies/acl/p: permission denied"), ReasonForbidden},
		{"forbidden-literal", errors.New("forbidden: token lacks capability"), ReasonForbidden},
		{"status-403", errors.New("request failed with status 403"), ReasonForbidden},
		{"code-403", errors.New("code 403 returned"), ReasonForbidden},
		{"not-found-literal", errors.New("not found"), ReasonNotFound},
		{"404", errors.New("unexpected 404 from server"), ReasonNotFound},
		{"500", errors.New("internal server error (500)"), ReasonBaoError},
		{"dial-error", errors.New("dial tcp 127.0.0.1:8200: connection refused"), ReasonBaoError},
		{"empty-message", errors.New(""), ReasonBaoError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyErr(tc.in); got != tc.want {
				t.Errorf("ClassifyErr(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
