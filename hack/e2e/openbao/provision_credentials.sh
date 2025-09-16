#!/usr/bin/env bash
set -euo pipefail

# ---- Inputs ----
OPENBAO_NS=${OPENBAO_NS:-openbao}
OPERATOR_NS=${OPERATOR_NS:-mto-system}
VAULT_ADDR=${VAULT_ADDR:-http://openbao.${OPENBAO_NS}.svc.cluster.local:8200}
VAULT_TOKEN=${VAULT_TOKEN:-root}
POLICY_NAME=${POLICY_NAME:-obx-e2e-read}
POLICY_FILE=${POLICY_FILE:-test/policies/obx-e2e-read.hcl}
SECRET_NAME=${SECRET_NAME:-mto-openbao-token}
SECRET_KEY=${SECRET_KEY:-token}
TOKEN_TTL=${TOKEN_TTL:-1h}

[ -f "$POLICY_FILE" ] || { echo "Policy file not found: $POLICY_FILE" >&2; exit 1; }

# Return ONLY the JSON body (strip headers and the "pod ... deleted" trailer)
kcurl_json() {
  kubectl -n "${OPENBAO_NS}" run curl --image=curlimages/curl:8.10.1 \
    --restart=Never --rm -i --tty -- \
    -sS -H "X-Vault-Token: ${VAULT_TOKEN}" -H "Content-Type: application/json" "$@" \
  | awk 'BEGIN{injson=0} /^[{\[]/ {injson=1} { if(injson) print }' \
  | sed -E '/^pod ".*" deleted$/d'
}

# Return just the HTTP code
kcurl_code() {
  kubectl -n "${OPENBAO_NS}" run curl --image=curlimages/curl:8.10.1 \
    --restart=Never --rm -i --tty -- \
    -sS -o /dev/null -w "%{http_code}\n" \
    --connect-timeout 2 --max-time 5 "$@" \
  | sed -n '1s/^\([0-9][0-9][0-9]\).*/\1/p'
}

echo ">> Waiting for OpenBao to be reachable at ${VAULT_ADDR}"
ok=0
for i in {1..90}; do
  code=$(kcurl_code "${VAULT_ADDR}/v1/sys/health" 2>/dev/null || echo 000)
  case "$code" in
    200|429|472|473) echo "   health OK (${code})"; ok=1; break ;;
    *)               echo "   waiting... (${code})"; sleep 2 ;;
  esac
done
[ "$ok" -eq 1 ] || { echo "OpenBao health never became OK"; exit 1; }

echo ">> Verifying admin token"
kcurl_json "${VAULT_ADDR}/v1/auth/token/lookup-self" >/dev/null

echo ">> Tuning 'secret/' to KV v2"
kcurl_json -X POST "${VAULT_ADDR}/v1/sys/mounts/secret/tune" \
  --data '{"options":{"version":"2"}}' >/dev/null || true

echo ">> Writing policy '${POLICY_NAME}' from ${POLICY_FILE}"
kcurl_json -X PUT "${VAULT_ADDR}/v1/sys/policies/acl/${POLICY_NAME}" \
  --data "$(jq -n --rawfile policy "${POLICY_FILE}" '{policy:$policy}')" >/dev/null

echo ">> Creating limited token"
echo ">> Debug: Creating token with policies [\"${POLICY_NAME}\"] ttl ${TOKEN_TTL} renewable true"
echo ">> Debug: Payload"
jq -n \
      --argjson policies "[\"${POLICY_NAME}\"]" \
      --arg ttl "${TOKEN_TTL}" \
      --argjson renewable true \
      '{policies:$policies,ttl:$ttl,renewable:$renewable}'

echo ">> Debug: jq input"
JQ_INPUT=$(jq -n \
  --argjson policies "[\"${POLICY_NAME}\"]" \
  --arg ttl "${TOKEN_TTL}" \
  --argjson renewable true \
  '{policies:$policies,ttl:$ttl,renewable:$renewable}')
echo "$JQ_INPUT"

echo ">> Debug: kcurl_json command"
echo "kcurl_json -X POST \"${VAULT_ADDR}/v1/auth/token/create\" --data '$JQ_INPUT'"

KCURL_OUTPUT=$(kcurl_json -X POST "${VAULT_ADDR}/v1/auth/token/create" --data "$JQ_INPUT")
echo ">> Debug: kcurl_json output"
echo "$KCURL_OUTPUT"

TOKEN=$(echo "$KCURL_OUTPUT" | jq -r '.auth.client_token')
echo ">> Debug: Extracted token: $TOKEN"
[ -n "${TOKEN}" ] && [ "${TOKEN}" != "null" ] || { echo "Failed to create token"; exit 1; }

echo ">> Storing token in ${OPERATOR_NS}/${SECRET_NAME}.${SECRET_KEY}"
kubectl create ns "${OPERATOR_NS}" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "${OPERATOR_NS}" delete secret "${SECRET_NAME}" --ignore-not-found >/dev/null 2>&1 || true
kubectl -n "${OPERATOR_NS}" create secret generic "${SECRET_NAME}" --from-literal="${SECRET_KEY}=${TOKEN}"

echo ">> Done."
