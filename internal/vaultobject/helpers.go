package vaultobject

import (
	"fmt"
	"strings"
)

// CleansePath removes duplicate slashes and leading/trailing slashes.
// Semantics mirror redhat-cop/vault-config-operator's utils.CleansePath.
func CleansePath(path string) string {
	return strings.Trim(strings.ReplaceAll(path, "//", "/"), "/")
}

// ToString stringifies values returned by the bao HTTP client.
//
//	nil      -> ""
//	string   -> itself
//	other    -> fmt.Sprint(v)
//
// VCO's upstream ToString does an unchecked type assertion to string and
// panics on non-string non-nil inputs. We return fmt.Sprint for robustness
// at a small semantic divergence.
func ToString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}
