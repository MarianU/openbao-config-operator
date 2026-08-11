package vaultobject

import "strings"

// CleansePath removes duplicate slashes and leading/trailing slashes.
// Semantics mirror redhat-cop/vault-config-operator's utils.CleansePath.
func CleansePath(path string) string {
	return strings.Trim(strings.ReplaceAll(path, "//", "/"), "/")
}
