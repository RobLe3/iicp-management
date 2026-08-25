# Drift detection and bounded reconciliation

Drift assessment is available only after a rollout reaches a terminal convergence state. It consumes fresh `AdapterInspectionV1` evidence and never contacts or changes a target.

```bash
iicp-management rollout assess-drift rollout.db rollout:example adapter-inspection.json
iicp-management --json rollout drift-status rollout.db rollout:example
```

The comparison uses the last verified receipt when available. Missing, stale, incomplete or mismatched evidence stays visible as unknown or drifted. It is never treated as success.

A bounded proposal requires an explicit classification:

```bash
iicp-management --json rollout propose-reconcile \
  rollout.db rollout:example target:fra-03 capability_runtime
```

Only `safe_metadata` and `capability_runtime` enter this path. Membership, trust or identity, secret-reference, irreversible and unclassified drift remain review-only.

The proposal grants no authority. Prepare and independently authorize a fresh exact local apply gate, then execute it through the existing owner-protected controller endpoint:

```bash
iicp-management rollout reconcile-target \
  rollout.db reconcile:proposal-id fresh-apply-gate.json \
  /run/user/$(id -u)/iicp-management.sock \
  --confirm operation:reconcile:fra-03
```

The gate must restore the proposal's desired digest from the observed generation and name the original operation as `related_operation_id`. A mismatch fails before target execution. After execution, collect a new inspection to prove convergence; the execution receipt alone does not rewrite the earlier observation.
