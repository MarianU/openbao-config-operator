# list and read mounts
path "sys/mounts" {
  capabilities = ["read"]
}
# (optional but handy) list enabled auth methods
path "sys/auth" {
  capabilities = ["read","list"]
}

# list and read ACL policies
path "sys/policies/acl" {
  capabilities = ["read","list"]
}
path "sys/policies/acl/*" {
  capabilities = ["read"]
}

# list and read Kubernetes auth roles
path "auth/kubernetes/roles" {
  capabilities = ["read","list"]
}
path "auth/kubernetes/role/*" {
  capabilities = ["read"]
}
