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

# manage transit keys (per-mount). The OpenBaoTransitKey controller
# reads, writes, and deletes /<mount>/keys/<name> and writes the
# mutable subset to /<mount>/keys/<name>/config. Wildcard mount path
# because the spec.path is operator-supplied.
path "+/keys"               { capabilities = ["read","list"] }
path "+/keys/*"             { capabilities = ["create","read","update","delete","list"] }
