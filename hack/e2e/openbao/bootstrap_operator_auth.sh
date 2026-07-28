#!/usr/bin/env bash
set -euo pipefail

# Bootstraps the operator's own bao identity so the operator process never
# holds a stored credential: it logs in with its ServiceAccount at
# auth/k8s-operator/login and gets a short-lived token bound to the
# operator-manage policy.
#
# Idempotent — safe to re-run any time (repair, policy update on upgrade).
#
# Run with a privileged token. The recommended flow keeps root down to two
# commands (see bootstrap-policy.hcl):
#   VAULT_TOKEN=<root> bao policy write obx-bootstrap hack/e2e/openbao/bootstrap-policy.hcl
#   VAULT_TOKEN=$(VAULT_TOKEN=<root> bao token create -field=token -policy=obx-bootstrap -ttl=20m) \
#     ./hack/e2e/openbao/bootstrap_operator_auth.sh
# For dev/kind (openbao in dev mode) plain VAULT_TOKEN=root works too.

# ---- Inputs ----
OPENBAO_NS=${OPENBAO_NS:-openbao}
OPERATOR_NS=${OPERATOR_NS:-mto-extension-openbao-system}
VAULT_ADDR=${VAULT_ADDR:-http://openbao.${OPENBAO_NS}.svc.cluster.local:8200}
VAULT_TOKEN=${VAULT_TOKEN:-root}
AUTH_MOUNT=${AUTH_MOUNT:-k8s-operator}
OPERATOR_ROLE=${OPERATOR_ROLE:-mto-extension-openbao}
OPERATOR_SA=${OPERATOR_SA:-mto-extension-openbao-controller-manager}
POLICY_NAME=${POLICY_NAME:-operator-manage}
POLICY_FILE=${POLICY_FILE:-hack/e2e/openbao/operator-policy.hcl}
TOKEN_TTL=${TOKEN_TTL:-1h}
AUDIENCE=${AUDIENCE:-openbao}
REVIEWER_SA=${REVIEWER_SA:-bao-token-reviewer}

[ -f "$POLICY_FILE" ] || { echo "Policy file not found: $POLICY_FILE" >&2; exit 1; }

# kcurl runs curl inside the openbao namespace, attached to the same network
# the bao pod resolves over. Same TTY/trailer quirks as
# provision_credentials.sh — see the comments there.
kcurl() {
  kubectl -n "${OPENBAO_NS}" run "curl-$$-${RANDOM}" --image=curlimages/curl:8.10.1 \
    --restart=Never --rm -i --quiet -- \
    -sS -H "X-Vault-Token: ${VAULT_TOKEN}" -H "Content-Type: application/json" "$@"
}

kcurl_json() {
  kcurl "$@" | sed -E '/^pod ".*" deleted$/d' | awk '/^[{[]/{p=1} p'
}

kcurl_code() {
  kubectl -n "${OPENBAO_NS}" run "curl-$$-${RANDOM}" --image=curlimages/curl:8.10.1 \
    --restart=Never --rm -i --quiet -- \
    -sS -o /dev/null -w "%{http_code}\n" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    --connect-timeout 2 --max-time 10 "$@" \
  | sed -n '1s/^\([0-9][0-9][0-9]\).*/\1/p'
}

echo ">> Verifying bootstrap token"
kcurl_json "${VAULT_ADDR}/v1/auth/token/lookup-self" >/dev/null

echo ">> Ensuring token-reviewer identity (${OPERATOR_NS}/${REVIEWER_SA})"
# The SA whose JWT bao presents to the apiserver for TokenReview, plus the
# auth-delegator grant and a long-lived token Secret. Mirrors the bootstrap
# chart's 10-token-reviewer.yaml so this script is self-sufficient on kind.
# Create-if-missing rather than apply: on MTO-managed clusters an admission
# webhook forbids updates to managed-prefix namespaces, and an apply against
# an existing namespace counts as an update.
kubectl get ns "${OPERATOR_NS}" >/dev/null 2>&1 || kubectl create ns "${OPERATOR_NS}"
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${REVIEWER_SA}
  namespace: ${OPERATOR_NS}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${REVIEWER_SA}-auth-delegator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
  - kind: ServiceAccount
    name: ${REVIEWER_SA}
    namespace: ${OPERATOR_NS}
---
apiVersion: v1
kind: Secret
metadata:
  name: ${REVIEWER_SA}
  namespace: ${OPERATOR_NS}
  annotations:
    kubernetes.io/service-account.name: ${REVIEWER_SA}
type: kubernetes.io/service-account-token
EOF

echo ">> Waiting for the reviewer token to materialize"
REVIEWER_JWT=""
for _ in $(seq 1 30); do
  REVIEWER_JWT=$(kubectl -n "${OPERATOR_NS}" get secret "${REVIEWER_SA}" \
    -o jsonpath='{.data.token}' 2>/dev/null | base64 -d || true)
  [ -n "${REVIEWER_JWT}" ] && break
  sleep 2
done
[ -n "${REVIEWER_JWT}" ] || { echo "Reviewer token never materialized" >&2; exit 1; }

echo ">> Enabling kubernetes auth at auth/${AUTH_MOUNT}"
ENABLE_CODE=$(kcurl_code -X POST "${VAULT_ADDR}/v1/sys/auth/${AUTH_MOUNT}" \
  --data '{"type":"kubernetes","description":"operator self-login (bootstrap-owned; do not manage via CRs)"}')
case "${ENABLE_CODE}" in
  200|204) ;;
  400) echo "   already enabled (400 path in use) — continuing" ;;
  *) echo "Failed to enable auth mount (HTTP ${ENABLE_CODE})" >&2; exit 1 ;;
esac

echo ">> Writing auth/${AUTH_MOUNT}/config"
CONFIG_BODY=$(jq -n --arg jwt "${REVIEWER_JWT}" \
  '{kubernetes_host:"https://kubernetes.default.svc", token_reviewer_jwt:$jwt}')
CONFIG_CODE=$(kcurl_code -X POST "${VAULT_ADDR}/v1/auth/${AUTH_MOUNT}/config" --data "${CONFIG_BODY}")
case "${CONFIG_CODE}" in
  200|204) ;;
  *) echo "Failed to write auth config (HTTP ${CONFIG_CODE})" >&2; exit 1 ;;
esac

echo ">> Writing policy '${POLICY_NAME}' from ${POLICY_FILE}"
POLICY_BODY=$(jq -n --rawfile policy "${POLICY_FILE}" '{policy:$policy}')
kcurl_json -X PUT "${VAULT_ADDR}/v1/sys/policies/acl/${POLICY_NAME}" --data "${POLICY_BODY}" >/dev/null
READ_POLICY=$(kcurl_code "${VAULT_ADDR}/v1/sys/policies/acl/${POLICY_NAME}" 2>/dev/null || echo 000)
[ "${READ_POLICY}" = "200" ] || { echo "Policy ${POLICY_NAME} failed to install (HTTP ${READ_POLICY})" >&2; exit 1; }

echo ">> Writing role '${OPERATOR_ROLE}' bound to ${OPERATOR_NS}/${OPERATOR_SA} (ttl=${TOKEN_TTL}, audience=${AUDIENCE})"
ROLE_BODY=$(jq -n \
  --arg sa "${OPERATOR_SA}" \
  --arg ns "${OPERATOR_NS}" \
  --arg policy "${POLICY_NAME}" \
  --arg ttl "${TOKEN_TTL}" \
  --arg aud "${AUDIENCE}" \
  '{bound_service_account_names:[$sa], bound_service_account_namespaces:[$ns],
    token_policies:[$policy], token_ttl:$ttl, audience:$aud}')
ROLE_CODE=$(kcurl_code -X POST "${VAULT_ADDR}/v1/auth/${AUTH_MOUNT}/role/${OPERATOR_ROLE}" --data "${ROLE_BODY}")
case "${ROLE_CODE}" in
  200|204) ;;
  *) echo "Failed to write role (HTTP ${ROLE_CODE})" >&2; exit 1 ;;
esac

READ_ROLE=$(kcurl_code "${VAULT_ADDR}/v1/auth/${AUTH_MOUNT}/role/${OPERATOR_ROLE}")
[ "${READ_ROLE}" = "200" ] || { echo "Role failed to install (HTTP ${READ_ROLE})" >&2; exit 1; }

echo ">> Done. The operator authenticates at auth/${AUTH_MOUNT}/login with role '${OPERATOR_ROLE}'."
echo "   No token Secret is created; the bootstrap token can now expire or be revoked."
