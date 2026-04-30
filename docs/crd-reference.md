# CRD reference

User-facing reference for the CRDs this operator installs. Appended to as each
story of the [VCO wrap roadmap](./plans/PLAN-vco-wrap-roadmap.md)
lands its primitive(s).

## Summary

| Kind | Group / Version | Scope | Purpose |
|---|---|---|---|
| `OpenBaoExtension` | `security.mto.stakater.com/v1alpha1` | Namespaced | Cluster-level connection + defaults for OpenBao integration. Reconciled by the `ClusterAuth` and `Tenant` controllers. |
| `OpenBaoPolicy` | `security.mto.stakater.com/v1alpha1` | Namespaced | Authors an OpenBao ACL policy at `sys/policies/acl/<name>`. Optionally scoped to an OpenBao namespace via `spec.openbaoNamespace` (X-Vault-Namespace). |
| `OpenBaoKubernetesAuthRole` | `security.mto.stakater.com/v1alpha1` | Namespaced | Authors an OpenBao Kubernetes-auth role at `auth/<spec.path>/role/<name>`. Binds service accounts in selected namespaces to bao policies. |
| `OpenBaoSecretEngine` | `security.mto.stakater.com/v1alpha1` | Namespaced | Manages a bao secret-engine mount lifecycle at `sys/mounts/<path>`. Discriminated-union spec selects engine kind: `kvV2`, `transit`, `pki`. Optionally scoped via `spec.openbaoNamespace`. Auth-method mounts are out of scope for this Kind. |
| `OpenBaoNamespace` | `security.mto.stakater.com/v1alpha1` | Namespaced | Owns a bao namespace at `sys/namespaces/<name>`. Nested via `spec.openbaoNamespace` as the parent. Delete is gracefully blocked until the bao namespace is empty. |
| `OpenBaoPKISecretEngineConfig` | `security.mto.stakater.com/v1alpha1` | Namespaced | Generates the root CA at `<path>/root/generate/internal` and writes URL config at `<path>/config/urls`. Pairs with an existing `OpenBaoSecretEngine` of kind=pki at the same path. **IsDeletable=false**: CR delete does not disable the bao mount (would destroy the private key). |
| `OpenBaoPKISecretEngineRole` | `security.mto.stakater.com/v1alpha1` | Namespaced | PKI issuance role at `<path>/roles/<name>`. Defines what certs may be issued from a PKI mount (allowed domains, key type/bits, EKU flags, TTL). Requires the mount to have a CA configured. |

---

## `OpenBaoPolicy`

Reconciles a CR to an OpenBao ACL policy. CRUD plus drift correction on every reconcile (event-driven; see [memory/project_vco_drift_gap](../../.claude/projects) for the periodic-resync gap).

### Sample

See [config/samples/security_v1alpha1_openbaopolicy.yaml](../config/samples/security_v1alpha1_openbaopolicy.yaml) for a runnable example:

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoPolicy
metadata:
  name: secret-reader
  namespace: mto-extension-openbao-system
spec:
  policy: |
    path "secret/data/public/*" {
      capabilities = ["read", "list"]
    }
```

### Spec fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `spec.policy` | string (HCL) | yes | — | Policy body in OpenBao's HCL syntax. |
| `spec.name` | string | no | `metadata.name` | Name used on the bao side. Takes precedence over `metadata.name` when set; must match `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`. |
| `spec.openbaoNamespace` | string | no | `""` (root) | Targets an OpenBao namespace via `X-Vault-Namespace`. Accepts empty (root), single-segment (`acme`), nested (`acme/sub`), with optional trailing slash. |

VCO's `spec.authentication` and `spec.connection` fields are **not** present — our operator uses a single token from `OpenBaoExtension.spec.server.tokenSecretRef` for all primitives. The namespace selector that lived on `spec.authentication.namespace` upstream is now `spec.openbaoNamespace`.

### Status

One condition: `Ready`. Reason values the controller sets:

| Reason | Meaning |
|---|---|
| `Reconciled` | Bao-side policy matches `spec.policy`. |
| `Invalid` | CR validation failed (reserved; `Policy` has no runtime validation beyond CRD schema). |
| `Forbidden` | Operator token lacks capability on `sys/policies/acl/*`. Update the operator's policy. |
| `NotFound` | 404 seen during drift check; self-heals on next reconcile. |
| `BaoError` | Any other non-2xx from OpenBao. `message` carries the raw server response. |

### Operational notes

- **Accessor placeholder substitution unsupported.** A CR whose `spec.policy` contains `${auth/<mount>/@accessor}` is rejected with `Ready=False`; the condition message names the placeholder and shows how to find the literal UUID. Hardcode it for now:

  ```bash
  bao auth list -format=json | jq -r '.["kubernetes/"].accessor'
  ```

- **Drift correction.** The controller re-checks the bao-side body every 5 minutes. An out-of-band edit (`bao policy write`) is overwritten on the next tick.
- **Force-delete footgun.** `kubectl delete --grace-period=0 --force` bypasses the finalizer and leaves the bao-side policy orphaned. Clean up with a direct HTTP DELETE to `sys/policies/acl/<name>` via a port-forward, or with the `bao` CLI if installed.
- **Bao-name collision protection.** Bao policy names are global; the `Policy` CRD is namespace-scoped. Two `Policy` CRs in different k8s namespaces that target the same bao policy name (same `metadata.name` with no `spec.name`, or same `spec.name`) are detected at reconcile time. The older `CreationTimestamp` wins; on tie, lex order of `<namespace>/<name>` decides. The losing CR surfaces `Ready=False, Reason=NameCollision` with a message naming the winning CR; no overwrite happens.

### RBAC

- `security.mto.stakater.com/openbaopolicies`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaopolicies/status`: `get, update, patch`
- `security.mto.stakater.com/openbaopolicies/finalizers`: `update`

No cluster-scoped or cross-resource permissions.

### Watches

- `Policy` CRs, filtered by `predicate.GenerationChangedPredicate` — only spec changes trigger reconciles. Status writes from the controller itself do not.

---

## OpenBaoKubernetesAuthRole

Reconciles a CR to an OpenBao Kubernetes-auth role at `auth/<spec.path>/role/<name>`. The role binds Kubernetes service accounts in selected namespaces to a list of bao policies. CRUD plus periodic drift correction; namespace label changes re-resolve selector-bound roles within seconds.

### Samples

Two runnable samples ship under `config/samples/`:

- [security_v1alpha1_kubernetesauthenginerole.yaml](../config/samples/security_v1alpha1_kubernetesauthenginerole.yaml) — literal namespace list. Use when the bound namespace set is known at apply time and does not move.
- [security_v1alpha1_kubernetesauthenginerole_selector.yaml](../config/samples/security_v1alpha1_kubernetesauthenginerole_selector.yaml) — label selector. Use when the bound namespace set is driven by labels and may grow or shrink at runtime.

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoKubernetesAuthRole
metadata:
  name: team-a-readers
  namespace: mto-extension-openbao-system
spec:
  path: kubernetes
  policies:
    - team-a-secret-reader
  targetServiceAccounts:
    - default
  targetNamespaces:
    targetNamespaceSelector:
      matchLabels:
        stakater.com/tenant: team-a
  tokenTTL: 1h
  tokenMaxTTL: 24h
```

### Spec fields

Duration fields (`tokenTTL`, `tokenMaxTTL`, `tokenExplicitMaxTTL`, `tokenPeriod`) accept bao-format duration strings — e.g. `1h`, `3600s`, `30m`.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `spec.path` | string | yes | — | Auth mount path. Bao writes to `auth/<path>/role/<name>`. |
| `spec.name` | string | no | `metadata.name` | Bao-side role name. Must match `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`. |
| `spec.policies` | string[] | yes | — | Bao policy names this role binds. MinItems=1. |
| `spec.targetServiceAccounts` | string[] | no | `["default"]` | Service account names inside each matched namespace. |
| `spec.targetNamespaces.targetNamespaces` | string[] | one of two | — | Literal list of namespace names. |
| `spec.targetNamespaces.targetNamespaceSelector` | LabelSelector | one of two | — | Label selector resolved against `corev1.Namespace`. |
| `spec.audience` | string | no | — | JWT audience claim bao verifies on login. |
| `spec.aliasNameSource` | enum | no | `serviceaccount_uid` | One of `serviceaccount_uid`, `serviceaccount_name`. |
| `spec.tokenTTL` | duration | no | bao default | Incremental token lifetime, referenced at renewal. |
| `spec.tokenMaxTTL` | duration | no | bao default | Hard cap for renewals. |
| `spec.tokenBoundCIDRs` | string[] | no | — | Restrict token use to these CIDR blocks. |
| `spec.tokenExplicitMaxTTL` | duration | no | bao default | Hard token lifetime cap that ignores renewal. |
| `spec.tokenNoDefaultPolicy` | bool | no | bao default | Suppress bao's `default` policy on issued tokens. |
| `spec.tokenNumUses` | int | no | bao default | Cap on token uses; `0` means unlimited. |
| `spec.tokenPeriod` | duration | no | bao default | Periodic token renewal interval. |
| `spec.tokenType` | enum | no | `default` | One of `service`, `batch`, `default`, `default-service`, `default-batch`. |

VCO's `spec.authentication` and `spec.connection` fields are **not** present — our operator uses a single token from `OpenBaoExtension.spec.server.tokenSecretRef` for all primitives.

Exactly one of `spec.targetNamespaces.targetNamespaces` or `spec.targetNamespaces.targetNamespaceSelector` must be set. Setting both, or neither, is rejected with `Ready=False reason=Invalid` (no requeue — fix the spec).

### Status

One condition: `Ready`. Reason values the controller sets:

| Reason | Meaning |
|---|---|
| `Reconciled` | Bao-side role matches the desired payload. |
| `Invalid` | XOR violation on `targetNamespaces` / `targetNamespaceSelector`, or empty literal list. |
| `Forbidden` | Operator token lacks capability on `auth/<path>/role/*`. Update the operator's policy. |
| `NotFound` | 404 seen during drift check; self-heals on next reconcile. |
| `BaoError` | Any other non-2xx from OpenBao. `message` carries the raw server response. |
| `NameCollision` | Another `OpenBaoKubernetesAuthRole` CR (different UID) targets the same `(spec.path, name)`. The older `CreationTimestamp` wins. |
| `InternalError` | k8s apiserver lookup failed during selector resolution or the cross-CR collision check. The fault is the apiserver, not bao. |

Status field `baoWritten` (bool) is the durable cleanup signal: it flips true after a successful upsert and is never cleared. The controller uses it on the deletion path to decide whether to call `BaoDelete`, so a CR that flipped `Ready=True→False` after writing (e.g. token revoked mid-life) still cleans up its bao role on delete.

### Operational notes

- **Selector resolution.** The controller watches `corev1.Namespace` with a `LabelChangedPredicate`. Adding the matching label to a new namespace, removing it, creating, or deleting a namespace all re-trigger reconciles for any selector-bound CR within seconds.
- **Empty selector match.** When the selector matches zero namespaces, the controller writes `["__no_namespace__"]` as a sentinel because bao rejects an empty bound list. Once a matching namespace appears, the watch fires and the role rebinds.
- **Drift correction.** The controller re-checks the bao-side role every 5 minutes. The bound-namespace list comparison is order-insensitive; an out-of-band edit (`bao write auth/.../role/...`) is overwritten on the next tick.
- **Force-delete footgun.** `kubectl delete --grace-period=0 --force` bypasses the finalizer and leaves the bao-side role orphaned. Clean up with a direct HTTP DELETE to `auth/<path>/role/<name>` via a port-forward, or with the `bao` CLI.
- **Bao-name collision protection.** Bao role identity is the full `auth/<path>/role/<name>` — two CRs with the same `metadata.name` on **different** auth mounts (different `spec.path`) do not collide. Two CRs with the same `(spec.path, name)` across k8s namespaces are detected at reconcile; older `CreationTimestamp` wins, lex-tiebreak on `<namespace>/<name>`.

### RBAC

- `security.mto.stakater.com/openbaokubernetesauthroles`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaokubernetesauthroles/status`: `get, update, patch`
- `security.mto.stakater.com/openbaokubernetesauthroles/finalizers`: `update`
- **`""/namespaces`**: `get, list, watch` (cluster-scoped) — required for selector resolution and the namespace-label watch.

This is the first cluster-scoped permission added by the VCO-wrapped CRDs. Audit/compliance reviewers should expect this delta when upgrading.

### Watches

- `OpenBaoKubernetesAuthRole` CRs, filtered by `predicate.GenerationChangedPredicate`.
- `corev1.Namespace`, filtered by `predicate.LabelChangedPredicate`. Map function fans label changes out to every CR whose `targetNamespaceSelector` matches the changed namespace's labels.

---

## `OpenBaoSecretEngine`

Reconciles a CR to a bao-side secret-engine mount at `sys/mounts/<spec.path>`. The discriminated-union spec selects which secret-engine kind to enable: `kvV2`, `transit`, or `pki`. Auth-method mounts are out of scope for this Kind — the kubernetes auth mount is enabled by `clusterauth` at startup; cert and JWT auth mounts will be modeled by a separate Kind when those primitives land.

Exactly one engine slot must be set; CRD-level XValidation + `IsValid` enforce the XOR.

### Sample

See [config/samples/security_v1alpha1_openbaosecretengine.yaml](../config/samples/security_v1alpha1_openbaosecretengine.yaml) for a runnable example:

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoSecretEngine
metadata:
  name: secret-kv
  namespace: mto-extension-openbao-system
spec:
  path: secret
  description: cluster-shared kv-v2
  kvV2: {}
```

### Spec fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `spec.path` | string | yes | — | Bao-side mount path (e.g. `secret`, `pki`, `transit`). Trailing slashes stripped before the API call. Anchored Pattern allows nested paths (`kv/cluster-a`). |
| `spec.description` | string | no | `""` | Free-form mount description; mirrored verbatim into bao. |
| `spec.openbaoNamespace` | string | no | `""` (root) | Targets an OpenBao namespace via `X-Vault-Namespace`. |
| `spec.kvV2` | object | one of | — | Selects a KV-v2 secret engine. Empty object is sufficient (kv-v2 default config). |
| `spec.transit` | object | one of | — | Selects a Transit secret engine. Stub for now; per-engine fields land with the Transit story. |
| `spec.pki` | object | one of | — | Selects a PKI secret engine. Pairs with `OpenBaoPKISecretEngineConfig` and `OpenBaoPKISecretEngineRole` CRs targeting the same path. |

### Status

One condition: `Ready`. Reasons:

| Reason | Meaning |
|---|---|
| `Reconciled` | Bao-side mount matches spec. |
| `Invalid` | XOR violation, empty path, or other spec-level failure. |
| `NameCollision` | Another CR (different UID) targets the same `(openbaoNamespace, path)` tuple. |
| `Forbidden` | Operator token lacks capability on `sys/mounts/*`. |
| `BaoError` | Any other non-2xx from OpenBao. |

### Operational notes

- **Idempotent enable.** Bao returns `400 "path is already in use"` when re-enabling at the same path. The wrapper treats this as success so reconciles after the first one are no-ops.
- **Drift correction is event-driven.** Description and KV-v2 options are compared against the bao read shape; a CR-spec edit triggers re-upsert. Out-of-band edits to mount config are not corrected until the CR is patched, or until the next 5-minute periodic resync.
- **Namespace isolation.** Same path in different OpenBao namespaces is not a collision — bao isolates mounts via `X-Vault-Namespace`.
- **Rename cleanup.** Changing `spec.path` (or `spec.openbaoNamespace`) tears down the previous bao mount before recording the new identity. `status.lastWrittenBaoName` and `status.lastWrittenOpenBaoNamespace` track the last-written identity.
- **Force-delete footgun.** `kubectl delete --grace-period=0 --force` bypasses the finalizer; clean up with a direct DELETE to `sys/mounts/<path>` via port-forward.

### RBAC

- `security.mto.stakater.com/openbaosecretengines`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaosecretengines/status`: `get, update, patch`
- `security.mto.stakater.com/openbaosecretengines/finalizers`: `update`

No cluster-scoped or cross-resource permissions.

### Watches

- `OpenBaoSecretEngine` CRs, filtered by `predicate.GenerationChangedPredicate`.

---

## `OpenBaoPKISecretEngineConfig`

Generates a root CA inside an existing PKI mount and publishes the URL distribution config (AIA / CRL / OCSP). Pairs with `OpenBaoSecretEngine` of kind=pki at the same path — this CR populates the mount, it does not enable it.

**Root-only in this release.** Intermediate CAs (CSR-emitting + external sign + set-signed) are deferred to a follow-up; the `pkiType` enum is open-ended so the addition is non-breaking.

**`IsDeletable=false`.** The CR's finalizer is released without touching bao on delete. Disabling a PKI mount destroys the private key irreversibly and silently invalidates every cert ever issued. Same applies to renames: `spec.path` change leaves an orphan CA at the old mount (logged) rather than risking key loss.

### Sample

See [config/samples/security_v1alpha1_openbaopkisecretengineconfig.yaml](../config/samples/security_v1alpha1_openbaopkisecretengineconfig.yaml):

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoPKISecretEngineConfig
metadata:
  name: pki-root
  namespace: mto-extension-openbao-system
spec:
  path: pki
  pkiType: root
  commonName: "Demo Root CA"
  ttl: "87600h"
  keyType: rsa
  keyBits: 4096
  subject:
    organization: ["Stakater Demo"]
    ou: ["Platform"]
    country: ["US"]
  urls:
    issuingCertificates: ["https://bao.example.com/v1/pki/ca"]
    crlDistributionPoints: ["https://bao.example.com/v1/pki/crl"]
```

### Spec fields

| Field | Type | Required | Description |
|---|---|---|---|
| `spec.path` | string | yes | PKI mount path. Must match an existing `OpenBaoSecretEngine` of kind=pki at the same path. |
| `spec.openbaoNamespace` | string | no | X-Vault-Namespace target. Empty = root. |
| `spec.pkiType` | enum | yes | Currently only `root` accepted. |
| `spec.commonName` | string | yes | X.509 CN of the generated CA cert. |
| `spec.ttl` | duration | no | CA cert validity. Bao default is short — set explicitly for any production CA. |
| `spec.keyType` | enum | no | `rsa` / `ec` / `ed25519`. Default rsa. |
| `spec.keyBits` | int | no | RSA: 2048\|3072\|4096. EC: 224\|256\|384\|521. Ignored for ed25519. |
| `spec.subject` | object | no | Multi-valued X.509 subject fields (Organization, OU, Country, …). |
| `spec.urls` | object | no | AIA / CRL / OCSP distribution points published in every issued cert. |

### Status

| Field | Description |
|---|---|
| `conditions[Ready]` | `Reconciled` / `Invalid` / `NameCollision` / `Forbidden` / `BaoError`. |
| `baoWritten` | True after first successful CA generate. |
| `lastWrittenBaoName` / `lastWrittenOpenBaoNamespace` | Identity of the last successful write; rename-cleanup is skipped (IsDeletable=false). |
| `phase` | `""` before first generate, `Active` after. |
| `caSerialNumber` | X.509 serial of the active CA, captured from bao on initial generate. |

### Operational notes

- **Idempotent on existing CA.** BaoWrite re-probes via ReadPKICA; if a CA exists, only URLs are updated. Generate is never called twice on the same mount.
- **Drift correction.** URL config is the only mutable surface once the CA is active. CR-spec changes to URL fields are applied; CR-spec changes to CA fields (commonName, ttl, keyType, keyBits, subject) are **silently ignored** because regenerating would destroy the private key — change those by creating a new mount + new CR.
- **Collision.** Two CRs at the same `(spec.path, spec.openbaoNamespace)` tuple → older `creationTimestamp` wins; loser `Ready=False, reason=NameCollision`.
- **Force-delete footgun.** `kubectl delete --grace-period=0 --force` releases the finalizer without the operator running cleanup. Same effect as the normal delete in this case — bao state is preserved either way.

### RBAC

- `security.mto.stakater.com/openbaopkisecretengineconfigs`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaopkisecretengineconfigs/status`: `get, update, patch`
- `security.mto.stakater.com/openbaopkisecretengineconfigs/finalizers`: `update`
- Bao token must have `update` on `<mount>/root/generate/internal`, `read` on `<mount>/cert/ca`, and `update` on `<mount>/config/urls`.

### Watches

- `OpenBaoPKISecretEngineConfig` CRs, filtered by `predicate.GenerationChangedPredicate`.

---

## `OpenBaoPKISecretEngineRole`

PKI issuance role at `<path>/roles/<name>`. Pairs with `OpenBaoPKISecretEngineConfig` at the same `spec.path` (the PKI mount must have a CA before roles can issue from it).

### Sample

See [config/samples/security_v1alpha1_openbaopkisecretenginerole.yaml](../config/samples/security_v1alpha1_openbaopkisecretenginerole.yaml):

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoPKISecretEngineRole
metadata:
  name: web-server
  namespace: mto-extension-openbao-system
spec:
  path: pki
  allowedDomains: ["*.demo.example.com"]
  allowSubdomains: true
  serverFlag: true
  keyType: rsa
  keyBits: 2048
  ttl: "720h"
  maxTtl: "8760h"
```

### Spec fields

| Field | Type | Description |
|---|---|---|
| `spec.path` | string | PKI mount path. Must match an existing `OpenBaoSecretEngine` of kind=pki. |
| `spec.name` | string | Bao-side role name. Defaults to `metadata.name`. |
| `spec.openbaoNamespace` | string | X-Vault-Namespace target. |
| `spec.allowedDomains` | string[] | CN/SAN allow-list for issued certs. |
| `spec.allowSubdomains` / `allowBareDomains` / `allowAnyName` / `allowGlobDomains` | bool | Domain-matching modifiers. |
| `spec.enforceHostnames` / `allowIpSans` | bool | Hostname / IP SAN gating. |
| `spec.serverFlag` / `clientFlag` / `codeSigningFlag` / `emailProtection` | bool | EKU permission flags. |
| `spec.keyType` | enum | `rsa` / `ec` / `ed25519` / `any`. |
| `spec.keyBits` | int | RSA: 2048\|3072\|4096. EC: 224\|256\|384\|521. |
| `spec.keyUsage` / `extKeyUsage` | string[] | X.509 usage strings (e.g. `DigitalSignature`, `ServerAuth`). |
| `spec.ttl` / `maxTtl` | duration | Issued-cert validity. |
| `spec.generateLease` / `noStore` / `requireCN` | bool | Per-issuance behaviour. |

`IsValid` rejects a spec that allows nothing — at least one of `allowAnyName`, `allowedDomains`, `allowGlobDomains`, `allowBareDomains`, `allowSubdomains` must be set; otherwise bao silently rejects every issuance.

### Status

Standard `Ready` condition. Reasons: `Reconciled`, `Invalid`, `NameCollision`, `Forbidden`, `BaoError`. Plus `lastWrittenBaoName` / `lastWrittenOpenBaoNamespace` for rename tracking.

### Operational notes

- **Drift correction.** The drift comparator sorts list-shaped fields (`allowedDomains`, `keyUsage`, `extKeyUsage`) before compare and treats unset spec fields as "bao default" so a CR that omits `keyBits` doesn't false-positive against bao's default of 2048.
- **Collision tuple is (mount path, role name, openbaoNamespace).** Same role name on a different mount or in a different bao namespace is not a collision.
- **IsDeletable=true.** CR delete removes the bao role. Issued certs remain valid until they expire — bao's PKI role is just an issuance gate, not a revocation list.

### RBAC

- `security.mto.stakater.com/openbaopkisecretengineroles`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaopkisecretengineroles/status`: `get, update, patch`
- `security.mto.stakater.com/openbaopkisecretengineroles/finalizers`: `update`
- Bao token must have `update` / `read` / `delete` on `<mount>/roles/*`.
