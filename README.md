<!-- markdownlint-disable MD013 -->

# mto-extension-openbao

MTO OpenBao Extension

## Go module setup for private repos

This project depends on private modules under `github.com/stakater-ab`.

Before running `make build` or `go mod tidy`, configure Go to treat them as private:

```bash
# Tell Go to skip proxy/caching for private modules
export GOPRIVATE=github.com/stakater-ab/*

# If you use SSH for GitHub (recommended):
git config --global url."ssh://git@github.com/".insteadOf "https://github.com/"
```

## OpenBao authentication

The operator holds no stored OpenBao credential. It selects an auth mode from
`BAO_AUTH_METHOD`:

- **`kubernetes`** (deployment default): the operator exchanges its projected
  ServiceAccount token at `auth/k8s-operator/login` for a short-lived bao
  token, cached until near expiry and re-acquired automatically on expiry or
  revocation. Requires a one-time bootstrap (below).
- **`token`** (default when the env var is unset — used by `make run`): static
  token from `VAULT_TOKEN`/`BAO_TOKEN`, the legacy behavior. You are
  responsible for the token's lifetime.

### Bootstrap (once per OpenBao server)

The bootstrap creates the operator's auth mount, the `operator-manage`
policy, and the login role. Run it with a privileged token — the recommended
flow keeps the root token down to two commands and hands the script a
temporary token instead:

```bash
export VAULT_ADDR=https://<openbao>:8200
VAULT_TOKEN=<root> bao policy write obx-bootstrap hack/e2e/openbao/bootstrap-policy.hcl
BOOT_TOKEN=$(VAULT_TOKEN=<root> bao token create -field=token -policy=obx-bootstrap -ttl=20m)
VAULT_TOKEN=${BOOT_TOKEN} ./hack/e2e/openbao/bootstrap_operator_auth.sh
```

The script is idempotent — re-run it any time (repair, or when a release
notes a policy update). On dev/kind, `make deploy` runs it for you with the
dev-mode root token. The temp token expires on its own; revoking the root
token afterwards is optional (a quorum of unseal keys can regenerate one via
`bao operator generate-root`).

## E2E

### Prerequisites

0. authenticated with GitHub CLI
1. install openbao and jq cli.
2. ensure openbao is running in the cluster at port 8200.
3. `export VAULT_ADDR="http://localhost:8200"`
4. run the bootstrap above (on dev-mode openbao, `make openbao-bootstrap-auth`)

### Setup

`./test/e2e/obx_e2e_setup.sh`

### Run test

`make test-e2e`
