#!/usr/bin/env bash
set -euo pipefail

# obx_e2e_setup.sh — create a read-only policy and token for E2E tests.
# Requires: bao CLI, jq, and VAULT_ADDR / VAULT_TOKEN env vars.

POLICY_NAME="${POLICY_NAME:-obx-e2e-read}"
POLICY_FILE="${POLICY_FILE:-test/policies/obx-e2e-read.hcl}"
TOKEN_NAME="${TOKEN_NAME:-obx-e2e}"

: "${VAULT_ADDR:?VAULT_ADDR must be set, e.g. http://localhost:8200}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set to an admin/root token}"

# Normalize address (strip trailing slash and any /ui/... suffix)
VAULT_ADDR="${VAULT_ADDR%/}"
case "$VAULT_ADDR" in */ui/*) VAULT_ADDR="${VAULT_ADDR%%/ui/*}";; esac

command -v bao >/dev/null || { echo "bao CLI not found in PATH" >&2; exit 1; }
command -v jq  >/dev/null || { echo "jq not found in PATH" >&2; exit 1; }
[ -f "$POLICY_FILE" ] || { echo "Policy file not found: $POLICY_FILE" >&2; exit 1; }


echo ">>> Ensuring Tenant CRD is installed"
if ! kubectl get crd tenants.tenantoperator.stakater.com >/dev/null 2>&1; then
  gh api \
    -H "Accept: application/vnd.github.raw" \
    "/repos/stakater-ab/tenant-operator/contents/config/crd/bases/tenantoperator.stakater.com_tenants.yaml?ref=${TENANT_CRD_REF}" \
    > "$TENANT_CRD_TMP"
  kubectl apply -f "$TENANT_CRD_TMP"
fi

echo ">>> Checking Bao server at $VAULT_ADDR"
VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_TOKEN" bao status >/dev/null

echo ">>> Writing policy $POLICY_NAME from $POLICY_FILE"
VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_TOKEN" \
  bao policy write "$POLICY_NAME" "$POLICY_FILE"

echo ">>> Creating orphan token bound to $POLICY_NAME"
out="$(VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$VAULT_TOKEN" \
  bao token create -orphan -policy="$POLICY_NAME" -display-name="$TOKEN_NAME" -format=json)"
new_token="$(echo "$out" | jq -r '.auth.client_token')"
[ -n "$new_token" ] && [ "$new_token" != "null" ] || { echo "Failed to create token"; echo "$out"; exit 1; }

echo ">>> Verifying token works (sys/mounts)"
VAULT_ADDR="$VAULT_ADDR" VAULT_TOKEN="$new_token" bao read sys/mounts >/dev/null

echo
echo "set new token:"
echo "export VAULT_TOKEN=\"$new_token\""
