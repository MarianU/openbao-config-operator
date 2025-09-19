package utils

import (
	"fmt"
	"strings"
)

// Canonicalize names for Bao artifacts and paths.
func canon(s string) string { return strings.ToLower(s) }

// Derive the actual Kubernetes namespace name from Tenant settings.
func NamespaceFull(tenant, nsShort string, withTenantPrefix bool) string {
	tenant = canon(tenant)
	nsShort = canon(nsShort)
	if withTenantPrefix {
		return tenant + "-" + nsShort
	}
	return nsShort
}

// RoleName returns the Bao Kubernetes-auth role name for a tenant namespace.
func RoleName(tenant, nsFull string) string {
	return canon(tenant) + "-" + canon(nsFull)
}

// PolicyNameEditor returns the Bao policy name for RW access at namespace scope.
func PolicyNameEditor(tenant, nsFull string) string {
	return RoleName(tenant, nsFull) + "-editor"
}

// KVv2NamespaceEditorPolicy renders a kv-v2 policy with RW caps for a namespace prefix.
// mount is the engine mount name (e.g., "secret"); env typically "prod".
func KVv2NamespaceEditorPolicy(mount, tenant, env, nsFull string) string {
	mount = strings.Trim(mount, "/")
	tenant = canon(tenant)
	env = canon(env)
	nsFull = canon(nsFull)

	data := fmt.Sprintf(`path "%s/data/tenants/%s/%s/%s/*" { capabilities = ["create","read","update","delete","list"] }`,
		mount, tenant, env, nsFull)
	meta := fmt.Sprintf(`path "%s/metadata/tenants/%s/%s/%s/*" { capabilities = ["read","list","delete"] }`,
		mount, tenant, env, nsFull)

	return data + "\n" + meta + "\n"
}
