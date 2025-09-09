# mto-extension-openbao
MTO OpenBao Extension

### Go module setup for private repos

This project depends on private modules under `github.com/stakater-ab`.

Before running `make build` or `go mod tidy`, configure Go to treat them as private:

```bash
# Tell Go to skip proxy/caching for private modules
export GOPRIVATE=github.com/stakater-ab/*

# If you use SSH for GitHub (recommended):
git config --global url."ssh://git@github.com/".insteadOf "https://github.com/"

## E2E

### Prerequisites

0. authenticated with GitHub CLI
1. install openbao and jq cli.
2. ensure openbao is running in the cluster at port 8200.
3. `export VAULT_ADDR="http://localhost:8200"`
4. `export VAULT_TOKEN="<root-or-admin-token>"`

### Setup
`./test/e2e/obx_e2e_setup.sh`

### Run test
`make test-e2e`