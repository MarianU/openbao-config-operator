package resource

import "strings"

// Reason values surfaced in the Ready status condition. These are stable
// strings that dashboards, alerts, and user automation can match against.
const (
	ReasonReconciled = "Reconciled"
	ReasonInvalid    = "Invalid"
	ReasonForbidden  = "Forbidden"
	ReasonNotFound   = "NotFound"
	ReasonBaoError   = "BaoError"
)

// ClassifyErr maps a bao HTTP client error to a Reason. Mirrors the
// isForbidden pattern in internal/controller/clusterauth/clusterauth_controller.go.
func ClassifyErr(err error) string {
	if err == nil {
		return ReasonReconciled
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "permission denied"),
		strings.Contains(msg, "forbidden"),
		strings.Contains(msg, "status 403"),
		strings.Contains(msg, "code 403"):
		return ReasonForbidden
	case strings.Contains(msg, "404"),
		strings.Contains(msg, "not found"):
		return ReasonNotFound
	default:
		return ReasonBaoError
	}
}
