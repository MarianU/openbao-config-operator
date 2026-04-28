# CRD reference

User-facing reference for the CRDs this operator installs. Appended to as each
story of the [VCO wrap roadmap](./plans/PLAN-vco-wrap-roadmap.md)
lands its primitive(s).

## Summary

| Kind | Group / Version | Scope | Purpose |
|---|---|---|---|
| `OpenBaoExtension` | `security.mto.stakater.com/v1alpha1` | Namespaced | Cluster-level connection + defaults for OpenBao integration. Reconciled by the `ClusterAuth` and `Tenant` controllers. |
| `Policy` | `security.mto.stakater.com/v1alpha1` | Namespaced | Authors an OpenBao ACL policy at `sys/policies/acl/<name>`. |
| `KubernetesAuthEngineRole` | `security.mto.stakater.com/v1alpha1` | Namespaced | Authors an OpenBao Kubernetes-auth role at `auth/<spec.path>/role/<name>`. Binds service accounts in selected namespaces to bao policies. |

---

## `Policy`

Reconciles a CR to an OpenBao ACL policy. CRUD plus periodic drift correction.

### Sample

See [config/samples/security_v1alpha1_policy.yaml](../config/samples/security_v1alpha1_policy.yaml) for a runnable example:

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: Policy
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

VCO's `spec.authentication` and `spec.connection` fields are **not** present — our operator uses a single token from `OpenBaoExtension.spec.server.tokenSecretRef` for all primitives.

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

- `security.mto.stakater.com/policies`: `get, list, watch, update, patch`
- `security.mto.stakater.com/policies/status`: `get, update, patch`
- `security.mto.stakater.com/policies/finalizers`: `update`

No cluster-scoped or cross-resource permissions.

### Watches

- `Policy` CRs, filtered by `predicate.GenerationChangedPredicate` — only spec changes trigger reconciles. Status writes from the controller itself do not.

### See also

- [PLAN-vco-st1-foundation-policy.md](./plans/PLAN-vco-st1-foundation-policy.md) — story that introduced the CRD.
- [ADR-0002](./adr/0002-vco-wrap-vs-fork.md) — why VCO types are wrapped, not forked.
- [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) — upstream attribution for the wrapped type file.

---

## `KubernetesAuthEngineRole`

Reconciles a CR to an OpenBao Kubernetes-auth role at `auth/<spec.path>/role/<name>`. The role binds Kubernetes service accounts in selected namespaces to a list of bao policies. CRUD plus periodic drift correction; namespace label changes re-resolve selector-bound roles within seconds.

### Samples

Two runnable samples ship under `config/samples/`:

- [security_v1alpha1_kubernetesauthenginerole.yaml](../config/samples/security_v1alpha1_kubernetesauthenginerole.yaml) — literal namespace list. Use when the bound namespace set is known at apply time and does not move.
- [security_v1alpha1_kubernetesauthenginerole_selector.yaml](../config/samples/security_v1alpha1_kubernetesauthenginerole_selector.yaml) — label selector. Use when the bound namespace set is driven by labels and may grow or shrink at runtime.

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: KubernetesAuthEngineRole
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
| `NameCollision` | Another `KubernetesAuthEngineRole` CR (different UID) targets the same `(spec.path, name)`. The older `CreationTimestamp` wins. |
| `InternalError` | k8s apiserver lookup failed during selector resolution or the cross-CR collision check. The fault is the apiserver, not bao. |

Status field `baoWritten` (bool) is the durable cleanup signal: it flips true after a successful upsert and is never cleared. The controller uses it on the deletion path to decide whether to call `BaoDelete`, so a CR that flipped `Ready=True→False` after writing (e.g. token revoked mid-life) still cleans up its bao role on delete.

### Operational notes

- **Selector resolution.** The controller watches `corev1.Namespace` with a `LabelChangedPredicate`. Adding the matching label to a new namespace, removing it, creating, or deleting a namespace all re-trigger reconciles for any selector-bound CR within seconds.
- **Empty selector match.** When the selector matches zero namespaces, the controller writes `["__no_namespace__"]` as a sentinel because bao rejects an empty bound list. Once a matching namespace appears, the watch fires and the role rebinds.
- **Drift correction.** The controller re-checks the bao-side role every 5 minutes. The bound-namespace list comparison is order-insensitive; an out-of-band edit (`bao write auth/.../role/...`) is overwritten on the next tick.
- **Force-delete footgun.** `kubectl delete --grace-period=0 --force` bypasses the finalizer and leaves the bao-side role orphaned. Clean up with a direct HTTP DELETE to `auth/<path>/role/<name>` via a port-forward, or with the `bao` CLI.
- **Bao-name collision protection.** Bao role identity is the full `auth/<path>/role/<name>` — two CRs with the same `metadata.name` on **different** auth mounts (different `spec.path`) do not collide. Two CRs with the same `(spec.path, name)` across k8s namespaces are detected at reconcile; older `CreationTimestamp` wins, lex-tiebreak on `<namespace>/<name>`.

### RBAC

- `security.mto.stakater.com/kubernetesauthengineroles`: `get, list, watch, update, patch`
- `security.mto.stakater.com/kubernetesauthengineroles/status`: `get, update, patch`
- `security.mto.stakater.com/kubernetesauthengineroles/finalizers`: `update`
- **`""/namespaces`**: `get, list, watch` (cluster-scoped) — required for selector resolution and the namespace-label watch.

This is the first cluster-scoped permission added by the VCO-wrapped CRDs. Audit/compliance reviewers should expect this delta when upgrading.

### Watches

- `KubernetesAuthEngineRole` CRs, filtered by `predicate.GenerationChangedPredicate`.
- `corev1.Namespace`, filtered by `predicate.LabelChangedPredicate`. Map function fans label changes out to every CR whose `targetNamespaceSelector` matches the changed namespace's labels.

### See also

- Roadmap: [PLAN-vco-wrap-roadmap.md](./plans/PLAN-vco-wrap-roadmap.md)
- [ADR-0002](./adr/0002-vco-wrap-vs-fork.md) — why VCO types are wrapped, not forked.
- [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) — upstream attribution for the wrapped type file.
