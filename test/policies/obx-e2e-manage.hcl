# mounts & auth listing
path "sys/mounts"            { capabilities = ["read","list"] }
path "sys/mounts/*"          { capabilities = ["create","read","update","delete","list","sudo"] }
path "sys/auth"              { capabilities = ["read","list","sudo","create","update"] }
path "sys/auth/*"            { capabilities = ["read","list","sudo","create","update","delete"] }

# manage OpenBao namespaces (sudo required)
path "sys/namespaces"        { capabilities = ["read","list"] }
path "sys/namespaces/*"      { capabilities = ["create","read","update","delete","list","sudo"] }



# manage ACL policies (REQUIRES sudo on sys/*)
path "sys/policies/acl"      { capabilities = ["read","list","sudo"] }
path "sys/policies/acl/*"    { capabilities = ["create","update","read","list","delete","sudo"] }

# manage kubernetes auth (per-mount). spec.path is operator-supplied
# on OpenBaoAuthMethod / OpenBaoKubernetesAuthEngineConfig /
# OpenBaoKubernetesAuthRole, so e2e fixtures using non-default mounts
# must be covered by wildcards. Mirrors the +/keys pattern below.
path "auth/+/config"         { capabilities = ["create","read","update","delete","list"] }
path "auth/+/role"           { capabilities = ["read","list"] }
path "auth/+/role/*"         { capabilities = ["create","read","update","delete","list"] }

# Cert auth method stores trusted CAs at /auth/<mount>/certs/<name>
# (not /role/<name>). OpenBaoCertAuthEngineRole writes/reads these.
path "auth/+/certs"          { capabilities = ["read","list"] }
path "auth/+/certs/*"        { capabilities = ["create","read","update","delete","list"] }

# manage identity store (groups, group-aliases, OIDC roles/keys).
# OpenBaoGroup writes to identity/group and reads identity/group/name/<name>.
# OpenBaoGroupAlias writes to identity/group-alias and reads by id.
# OpenBaoIdentityTokenRole writes to identity/oidc/role/<name>; the role
# references a pre-existing identity/oidc/key/<key> (not managed by the
# operator today — the e2e suite writes one directly).
path "identity/group"            { capabilities = ["create","update"] }
path "identity/group/name/*"     { capabilities = ["create","read","update","delete","list"] }
path "identity/group/id"         { capabilities = ["list"] }
path "identity/group/id/*"       { capabilities = ["create","read","update","delete","list"] }
path "identity/group-alias"      { capabilities = ["create","update"] }
path "identity/group-alias/id"   { capabilities = ["list"] }
path "identity/group-alias/id/*" { capabilities = ["create","read","update","delete","list"] }
path "identity/oidc/role/*"      { capabilities = ["create","read","update","delete","list"] }
path "identity/oidc/key/*"       { capabilities = ["create","read","update","delete","list"] }

# manage transit keys (per-mount). The OpenBaoTransitKey controller
# reads, writes, and deletes /<mount>/keys/<name> and writes the
# mutable subset to /<mount>/keys/<name>/config. Wildcard mount path
# because the spec.path is operator-supplied.
path "+/keys"               { capabilities = ["read","list"] }
path "+/keys/*"             { capabilities = ["create","read","update","delete","list"] }

# manage PKI engines (per-mount). The OpenBaoPKISecretEngineConfig
# controller calls /<mount>/root/generate/<type> to create the root CA
# and reads /<mount>/cert/ca etc. The OpenBaoPKISecretEngineRole
# controller manages /<mount>/roles/<name>. Mount path is
# operator-supplied so the leading `+` is the mount segment.
path "+/root/generate/*"    { capabilities = ["create","read","update","sudo"] }
path "+/cert/*"             { capabilities = ["read"] }
path "+/roles"              { capabilities = ["read","list"] }
path "+/roles/*"            { capabilities = ["create","read","update","delete","list"] }
path "+/issuers"            { capabilities = ["read","list"] }
path "+/issuers/*"          { capabilities = ["create","read","update","delete","list"] }
path "+/config/*"           { capabilities = ["create","read","update","delete","list"] }

# Same set of permissions, but for paths inside any direct child
# OpenBao namespace. The leading `+` matches one bao-namespace
# segment, so `+/sys/policies/acl/*` covers `team-a/sys/policies/acl/*`,
# `team-b/...`, `shared/...`. Required because every primitive that
# carries spec.openbaoNamespace routes its bao API calls to the
# referenced namespace via X-Vault-Namespace; a root-only policy
# returns 403 for them.
path "+/sys/mounts"          { capabilities = ["read","list"] }
path "+/sys/mounts/*"        { capabilities = ["create","read","update","delete","list","sudo"] }
path "+/sys/auth"            { capabilities = ["read","list","sudo","create","update"] }
path "+/sys/auth/*"          { capabilities = ["read","list","sudo","create","update","delete"] }
path "+/sys/policies/acl"    { capabilities = ["read","list","sudo"] }
path "+/sys/policies/acl/*"  { capabilities = ["create","update","read","list","delete","sudo"] }
path "+/auth/+/config"       { capabilities = ["create","read","update","delete","list"] }
path "+/auth/+/role"         { capabilities = ["read","list"] }
path "+/auth/+/role/*"       { capabilities = ["create","read","update","delete","list"] }
path "+/+/keys"              { capabilities = ["read","list"] }
path "+/+/keys/*"            { capabilities = ["create","read","update","delete","list"] }
path "+/+/root/generate/*"   { capabilities = ["create","read","update","sudo"] }
path "+/+/cert/*"            { capabilities = ["read"] }
path "+/+/roles"             { capabilities = ["read","list"] }
path "+/+/roles/*"           { capabilities = ["create","read","update","delete","list"] }
path "+/+/issuers"           { capabilities = ["read","list"] }
path "+/+/issuers/*"         { capabilities = ["create","read","update","delete","list"] }
path "+/+/config/*"          { capabilities = ["create","read","update","delete","list"] }
