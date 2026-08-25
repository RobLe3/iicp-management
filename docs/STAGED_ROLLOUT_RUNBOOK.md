# Staged rollout runbook

This workflow coordinates already-authorized local apply gates. It does not create authorization and it never contacts a target during validation or creation.

## Prepare

Create a rollout manifest with one required target in batch `0`, contiguous later batch numbers, and one exact `LocalApplyGateV1` per target. Every gate must use the manifest's administrative domain and audience. Create a local executor map separately:

```json
{
  "executors": {
    "controller:canary": "/run/user/1000/iicp-management-canary.sock",
    "controller:fleet": "/run/user/1000/iicp-management-fleet.sock"
  }
}
```

The map is deployment-local and is not canonical rollout state.

## Validate and create

```bash
iicp-management rollout validate rollout.json
iicp-management rollout create rollout.db rollout.json
iicp-management --json rollout status rollout.db rollout:2026-08-25
```

Creation is idempotent only when the run identifier and canonical manifest digest both match. Reusing an identifier for different content fails.

## Execute a batch

```bash
iicp-management rollout run-batch rollout.db rollout:2026-08-25 executors.json \
  --confirm rollout:2026-08-25
```

The command executes current-batch targets sequentially. It sends each embedded gate to the configured local controller endpoint. A failed canary holds the run before later targets. Inspect status before proceeding.

## Pause, resume and retry

```bash
iicp-management rollout pause rollout.db rollout:2026-08-25
iicp-management rollout resume rollout.db rollout:2026-08-25
iicp-management rollout retry-target rollout.db rollout:2026-08-25 target:fra-03 \
  executors.json --confirm rollout:2026-08-25
```

Only a deferred target can be retried. Resume does not silently retry a failed or rejected operation.

## Partial convergence

A final batch with unresolved targets is `partially_converged`, not successful. Administrative acceptance requires a signed `iicp.management-partial-acceptance.v1` artifact bound to the run digest and current ledger version:

```bash
iicp-management rollout accept-partial rollout.db acceptance.json operator-public-key.b64
```

This records that the operator accepted the reported disposition. It does not modify targets or erase failures. Keep the rollout database, manifests and lifecycle receipts as the local evidence record.
