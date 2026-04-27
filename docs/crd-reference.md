# CRD reference

User-facing reference for the CRDs this operator installs. Appended to as each
story of the [VCO cherry-pick roadmap](./plans/PLAN-vco-cherrypick-roadmap.md)
lands its primitive(s).

## Summary

| Kind | Group / Version | Scope | Purpose |
|---|---|---|---|
| `OpenBaoExtension` | `security.mto.stakater.com/v1alpha1` | Namespaced | Cluster-level connection + defaults for OpenBao integration. Reconciled by the `ClusterAuth` and `Tenant` controllers. |
| `Policy` | `security.mto.stakater.com/v1alpha1` | Namespaced | Authors an OpenBao ACL policy at `sys/policies/acl/<name>`. |

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
- [ADR-0002](./adr/0002-vco-fork-vs-cherrypick.md) — why VCO types are cherry-picked, not forked.
- [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) — upstream attribution for the copied type file.
