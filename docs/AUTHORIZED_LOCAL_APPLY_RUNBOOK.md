# Authorized local apply: disposable recovery rehearsal

This rehearsal uses a temporary controller database, owner-protected local IPC,
and either the synthetic adapter or a temporary `RuntimeConfigV1` file. It does
not contact an IICP Directory or modify a running node.

## Reproduce the lifecycle tests

From a clean checkout:

```bash
cargo test --locked --test apply_gate
cargo test --locked --test controller_and_adapters
```

The tests cover exact plan acceptance, apply confirmation, capability-scoped
execution, independent verification, exact reversal, duplicate submission and
restart from `started` and `adapter_reported` journal phases. Temporary files
and SQLite databases are removed when each test completes.

## Operator sequence

Start one executor with one configured target:

```bash
iicp-management-controller serve-executor \
  "$XDG_RUNTIME_DIR/iicp-management.sock" /tmp/iicp-controller.db operator.pub \
  controller:local domain:local runtime-config-v1 runtime:test /tmp/runtime.json
```

Then use the signed artifacts produced by the planning and authorization layer:

```bash
iicp-management preview-apply apply-request.json
iicp-management request-apply "$XDG_RUNTIME_DIR/iicp-management.sock" \
  apply-request.json --confirm operation:test
iicp-management execute-apply "$XDG_RUNTIME_DIR/iicp-management.sock" \
  apply-request.json --confirm operation:test

iicp-management preview-recovery recovery-request.json
iicp-management request-recovery "$XDG_RUNTIME_DIR/iicp-management.sock" \
  recovery-request.json --confirm recovery:test
iicp-management execute-recovery "$XDG_RUNTIME_DIR/iicp-management.sock" \
  recovery-request.json --confirm recovery:test
```

Authorization and execution are deliberately separate. If the process stops
after execution starts, the restarted controller reads its durable journal and
observes the target before doing anything else. It never retries an uncertain
mutation automatically. A completed duplicate returns the stored lifecycle
receipt without invoking the adapter.

Delete only the temporary socket, database, runtime file and adapter-state file
created for this rehearsal. This runbook grants no production deployment or
remote-management authority.
