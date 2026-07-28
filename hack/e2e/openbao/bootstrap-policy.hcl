# obx-bootstrap — the policy for the TEMPORARY token an admin mints to run
# bootstrap_operator_auth.sh, so the root token itself never touches the
# script, a Job, or CI. Root's only job is two commands:
#
#   VAULT_TOKEN=<root> bao policy write obx-bootstrap hack/e2e/openbao/bootstrap-policy.hcl
#   VAULT_TOKEN=<root> bao token create -policy=obx-bootstrap -ttl=20m
#
# TTL is the bound; do NOT add a tight -use-limit — num_uses counts every
# request including lookups and verify-reads, and would kill the script
# midway. Grants are exactly the writes the bootstrap performs, nothing more.

# verify the token before doing anything (script sanity check)
path "auth/token/lookup-self"        { capabilities = ["read"] }

# enable + read back the operator's dedicated auth mount
path "sys/auth"                      { capabilities = ["read"] }
path "sys/auth/k8s-operator"         { capabilities = ["create","update","sudo"] }

# write + read back the mount's kubernetes config and the operator role
path "auth/k8s-operator/config"      { capabilities = ["create","update","read"] }
path "auth/k8s-operator/role/*"      { capabilities = ["create","update","read"] }

# write + read back the operator's policy
path "sys/policies/acl/operator-manage" { capabilities = ["create","update","read"] }
