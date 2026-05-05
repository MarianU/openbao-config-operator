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

# manage Kubernetes auth roles (no sudo needed)
path "auth/kubernetes/*" { capabilities = ["create","read","update","delete","list"] }
path "auth/kubernetes/roles" { capabilities = ["read","list"] }
path "auth/kubernetes/role/*"{ capabilities = ["create","update","read","list","delete"] }
