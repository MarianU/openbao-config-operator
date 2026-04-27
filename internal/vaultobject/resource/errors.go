package resource

import (
	"errors"
	"net/http"

	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
)

// Reason values surfaced in the Ready status condition. These are stable
// strings that dashboards, alerts, and user automation can match against.
const (
	ReasonReconciled    = "Reconciled"
	ReasonInvalid       = "Invalid"
	ReasonForbidden     = "Forbidden"
	ReasonNotFound      = "NotFound"
	ReasonBaoError      = "BaoError"
	ReasonNameCollision = "NameCollision"
	// ReasonInternalError covers controller-side preparation failures (accessor
	// resolution, TLS config setup, k8s lookups during PrepareInternalValues)
	// that have nothing to do with bao itself. Lumping them under BaoError
	// would mislead an operator paging on a Ready=False with reason=BaoError
	// into checking the bao server when the fault is in our preparation step.
	ReasonInternalError = "InternalError"
)

// ErrNameCollision is returned by a primitive's BaoWrite callback when it
// detects another CR (different UID) targeting the same bao-side name.
// Bao identifiers (policy names, role names, mount paths) are global within
// a bao namespace; our CRDs are k8s-namespace-scoped. Without this guard,
// two CRs in different k8s namespaces with the same metadata.name (or the
// same spec.name) would silently overwrite each other on every reconcile.
//
// Wrap with fmt.Errorf("%w: ...", ErrNameCollision, ...) so callers can
// errors.Is-detect it; ClassifyErr maps it to ReasonNameCollision.
var ErrNameCollision = errors.New("bao name collision")

// ErrInternal marks failures that are controller-side (k8s apiserver List,
// in-process state resolution) rather than bao-side. Wrap with
// fmt.Errorf("%w: ...", ErrInternal, ...) at the BaoWrite callsite so
// ClassifyErr maps the error to ReasonInternalError instead of misleading
// operators into checking the bao server.
var ErrInternal = errors.New("controller internal error")

// ClassifyErr maps a bao client error to a Reason. Detection is structured:
// the wrapper at internal/client tags every SDK error with HTTP status via
// *baoclient.StatusError, so we never have to string-match an error
// message and risk misclassifying a 500 whose body happens to mention
// "not found".
func ClassifyErr(err error) string {
	if err == nil {
		return ReasonReconciled
	}
	if errors.Is(err, ErrNameCollision) {
		return ReasonNameCollision
	}
	if errors.Is(err, ErrInternal) {
		return ReasonInternalError
	}
	var se *baoclient.StatusError
	if errors.As(err, &se) {
		switch se.StatusCode {
		case http.StatusForbidden:
			return ReasonForbidden
		case http.StatusNotFound:
			return ReasonNotFound
		default:
			return ReasonBaoError
		}
	}
	// Non-status errors: network failures, context cancellations, etc.
	return ReasonBaoError
}
