# Database Secret Engine — Operator Design

Status: **Design** (implementation in progress)
Scope: `openbao-config-operator` extension to manage the **database secret engine**
via two new CRDs. Nothing here references a specific cluster, tenant, or deployment.

---

## 1. Goal

Let the OpenBao config operator manage the database secret engine end-to-end, while
leaving **mount creation with the operator deployment**:

1. The `database/` secret-engine mount is enabled **as part of the openbao-operator
   deployment** (the operator-provisioning step), not by a CR and not by extending
   `OpenBaoSecretEngine` (which stays kv/transit/pki-only).
2. Each database deployment ships its **own `OpenBaoDatabaseEngineConfig`** (a
   connection/plugin config) into the shared `database/` mount — e.g. a MariaDB/MySQL
   deployment owns its connection, a PostgreSQL deployment owns its connection, and so
   on. Connection names are deployment-scoped and need not match the mount.
3. Each app that needs dynamic credentials ships an `OpenBaoDatabaseRole` (static role)
   targeting its connection.

The **mount path is generic** (`database/`); a connection's plugin and target database
are what distinguish entries, not the mount name.

## 2. Non-goals

- Not re-hosting any database engine.
- Not changing `OpenBaoSecretEngine` (no `database` type added).
- No generic "write arbitrary path" escape hatch.
- No new database plugin authoring — only wiring OpenBao's shipped plugins
  (`mysql-database-plugin`, `postgresql-database-plugin`, etc.), so which engines are
  "supported" is bounded by the OpenBao build.

## 3. Current state

- `OpenBaoSecretEngine.EngineType()` returns only `kv`/`transit`/`pki`; there is no database mount CR.
- The operator has no database-config or database-role CRD, no `database/config/*` /
  `database/roles/*` client operation in `internal/client/bao_client.go`, and no
  `operator-manage` grant for `database/*`.

## 4. Mount (deployment-owned, operator-agnostic)

The `database/` secret-engine mount is enabled idempotently **as part of
deploying/provisioning the operator** (same step that bootstraps the operator identity
and already enables `secret/` and the auth mounts) — `POST /sys/mounts/database`
with `type=database`. The operator neither owns nor creates the mount; it only writes
configs and roles beneath it.

> If a database engine mount already exists at a migration path, deployments whose VSO
> consumers read from that old path must be repointed to `database/` and validated
> before the old mount is retired (see §6.4).

## 5. Operator extension

Mount creation is out of scope, so the extension is exactly **two new CRDs** plus
client ops, controllers, RBAC, and a policy grant.

### 5.1 `OpenBaoDatabaseEngineConfig` → `database/config/<connection>`

Connections are written with `Logical().Write("<mount>/config/<connection>", …)`
(a config write, distinct from `OpenBaoKVSecret`).

| field | kind | notes |
|---|---|---|
| `spec.mount` | string | DB engine mount path (default `database`). |
| `spec.name` | string,opt | Overrides `metadata.name` (DNS-1123), mirroring other CRs. |
| `spec.pluginName` | string | e.g. `mysql-database-plugin`, `postgresql-database-plugin`. |
| `spec.connectionUrl` | string | Template with `{{username}}:{{password}}@…` placeholders. |
| `spec.credentialsRef` | k8s SecretRef | Connection admin `username`/`password`; read via the existing `readSecretRef` pattern; operator **watches the Secret** → re-reconciles on rotation (same as the OIDC/kubernetes-engine secret refs). |
| `spec.allowedRoles` | []string | Roles permitted on this connection (server-enforced). |
| `spec.verifyConnection` | bool | default true. |
| connection options | — | `maxOpenConnections`, `maxIdleConnections`, `maxConnectionLifetime`; TLS fields (`tlsServerName`, client-cert ref) where the plugin supports mTLS. |
| `spec.openbaoNamespace` | string | empty = root. |
| `spec.deletionPolicy` | enum | **default `Retain`** (connection is referenced by roles / holds admin creds). |

### 5.2 `OpenBaoDatabaseRole` → `database/roles/<name>`

Mirrors the PKI role CRD; written with `Logical().Write("<mount>/roles/<name>", …)`.

| field | kind | notes |
|---|---|---|
| `spec.mount`, `spec.name`, `spec.openbaoNamespace` | | as above. |
| `spec.dbName` | string | the connection name this role targets. |
| `spec.creationStatements` / `rotationStatements` / `revocationStatements` / `rollbackStatements` | []string | SQL (go-template vars `{{name}}`, `{{password}}`). |
| `spec.credentialType` | enum | `password` for these engines. |
| `spec.defaultTtl`, `spec.maxTtl` | duration | lease bounds for minted credentials. |
| `spec.deletionPolicy` | enum | **Retain** — the operator must never drop a role that live VSO consumers depend on. |
| status | | `Ready`/`Sync`; express the `dbName` dependency for ordering. |

Both CRDs use `security.mto.stakater.com/v1alpha1`, namespaced, and follow the existing
credential-resolution + drift-comparator conventions.

### 5.3 Client ops (`internal/client/bao_client.go`)

Via the wrapped `vault.Client.Logical()`:
- `WriteDatabaseConnection` / `ReadDatabaseConnection` / `DeleteDatabaseConnection` → `<mount>/config/<connection>`
- `WriteDatabaseRole` / `ReadDatabaseRole` / `DeleteDatabaseRole` → `<mount>/roles/<name>`
- `ListDatabaseConnections` / `ListDatabaseRoles` → `LIST` for inventory/drift
- `ReadDatabaseConnectionHealth` / ping → `<mount>/ping/<connection>` for `Readiness` when `verifyConnection=true`

### 5.4 Controllers

Two controllers mirroring the PKI config/role controllers plus:
- watch the `credentialsRef` Secret → requeue on rotation;
- a role waits for / re-checks its `dbName` connection;
- a finalizer honoring `deletionPolicy`.

### 5.5 RBAC (`config/rbac/role.yaml`)

The operator ClusterRole enumerates resources explicitly. Add:
- `openbaodatabaseengineconfigs`, `openbaodatabaseroles` (get/list/watch/create/update/patch/delete)
- `openbaodatabaseengineconfigs/finalizers`, `openbaodatabaseroles/finalizers`

### 5.6 `operator-manage` policy grants

Add to the inline `operator-manage` policy (root, plus `+/…` child mirrors when
namespaces are used) in the operator-provisioning playbook:

```
# database secret engine (OpenBaoDatabaseEngineConfig / OpenBaoDatabaseRole)
path "database/config/*" { capabilities = ["create","read","update","delete","patch"] }
path "database/roles/*"  { capabilities = ["create","read","update","delete","patch"] }
path "database/ping/*"   { capabilities = ["update"] }
```

The mount enable is covered separately at deployment time (§4); the existing `sys/mounts/*`
grant is not needed for per-connection management once the mount exists.

### 5.7 Release pipeline

- Build + publish `ghcr.io/MarianU/openbao-config-operator:0.0.7`.
- Rebuild the embedded chart subchart tarball (`charts/openbao-config-operator-*.tgz`)
  so ArgoCD installs/reconciles the two new CRDs.
- Re-run the operator-provisioning step to enable the `database/` mount and push the
  `database/*` policy grants.

## 6. Adoption pattern

### 6.1 One mount, deployment-owned connections

A single `database/` mount hosts every connection. OpenBao supports multiple plugin
connections per mount, so MariaDB/MySQL and PostgreSQL connections coexist under it;
each connection is created by the deployment that owns that database.

### 6.2 Per-deployment connection config

Each database deployment adds one co-located `OpenBaoDatabaseEngineConfig`:

| Owning deployment | plugin | `connection_url` template shape | creds source |
|---|---|---|---|
| MariaDB/MySQL app | `mysql-database-plugin` | `{{username}}:{{password}}@tcp(<db-host>:3306)/` | k8s secret (admin via `credentialsRef`) |
| PostgreSQL app | `postgresql-database-plugin` | `postgresql://{{username}}:{{password}}@<db-host>:5432/…` (+ SSL/cert where used) | k8s secret (superuser via `credentialsRef`) |

`spec.mount: database` on every config. The operator resolves `credentialsRef` from a
k8s Secret and requeues on rotation, so admin credentials never live on the CR.

### 6.3 Roles

Apps that mint dynamic credentials add an `OpenBaoDatabaseRole` targeting their
connection (`spec.dbName`). Statement templates and TTL are app-specific; existing,
already-in-use roles must be reproduced **byte-for-byte** when adopted and must use
`deletionPolicy: Retain`.

### 6.4 Legacy-mount migration (only when a prior mount must move)

If apps currently read from an older database mount path, after the operator recreates
their connections/roles under `database/`, repoint the app VSO consumers to the new
mount, verify they are synced, then retire the old mount. Never remove an old mount
while any consumer still targets it.

## 7. Rollout order

1. Operator: CRDs + controllers + client ops + RBAC + tests; build/publish `0.0.7`;
   rebuild chart subchart; sync CRDs.
2. Operator-provisioning step: enable `database/` mount; push `database/*` policy grants.
3. First deployment adopts its connection + existing roles under `database/`; **validate
   any VSO consumers that use them before proceeding**.
4. Remaining deployments add their connections (+ roles) co-located in their charts.
5. Retire any legacy database mount once all consumers are repointed.
6. Observe operator conditions; confirm per-app dynamic creds still mint/rotate.

## 8. Risks / open items

- **Legacy-mount migration** (§6.4) is the highest-risk step; gate it on consumer sync.
- **TLS/mTLS** connection options must be supported by the plugin and by the CR so
  deployments that require client certificates can express them; verify against the
  deployed OpenBao plugin set.
- **Admin credentials** for each connection must be supplied via a k8s Secret ref before
  the config CR reconciles (verify-connection will otherwise fail).
- **`database/ping/*` grant** must be in place or `verifyConnection` must be off during
  adoption; otherwise readiness reports `Ready=False`.
- **`OpenBaoSecretEngine` untouched** — confirm the operator's `sys/mounts/*` grant is not
  relied on for DB mount creation (the mount is deployment-owned).
