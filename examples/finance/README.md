# Finance management walkthrough

This disposable example demonstrates the read-only operator surface. It uses no
credentials, production identifiers or remote controller. Run it from the
repository root.

```bash
cargo run --locked --bin iicp-management -- validate \
  examples/finance/desired-state.json

cargo run --locked --bin iicp-management -- --json plan \
  examples/finance/desired-state.json \
  examples/finance/accepted-state.json

cargo run --locked --bin iicp-management -- diff \
  examples/finance/plan.json

cargo run --locked --bin iicp-management -- show stored-policies \
  examples/finance/proposed-workspace.json

cargo run --locked --bin iicp-management -- show effective-policy \
  examples/finance/proposed-workspace.json \
  examples/finance/facts-us.json binding:finance

cargo run --locked --bin iicp-management -- simulate \
  examples/finance/current-workspace.json \
  examples/finance/proposed-workspace.json \
  examples/finance/facts-us.json binding:finance

cargo run --locked --bin iicp-management -- explain decision \
  examples/finance/proposed-workspace.json \
  examples/finance/facts-us.json binding:finance \
  urn:iicp:intent:finance:analysis:v1 decision:finance:1

cargo run --locked --bin iicp-management -- verify-receipt \
  examples/finance/receipt.json examples/finance/plan.json domain:finance
```

The proposed policy denies the US candidate because the mandatory EU policy
does not match. The simulation reports the change from `allow` to `deny`, and
the explanation identifies `policy:eu-processing` as determining the result.
These are policy and evidence projections; no provider is selected and no state
is changed.

The negative fixtures demonstrate fail-closed behavior:

```bash
# Unknown required security semantics are rejected.
cargo run --locked --bin iicp-management -- validate \
  examples/finance/unknown-required-extension.json

# A receipt whose plan binding was changed is rejected.
cargo run --locked --bin iicp-management -- verify-receipt \
  examples/finance/receipt-tampered.json examples/finance/plan.json domain:finance
```

Use `--json` immediately after the binary name for deterministic automation
output. Human output is deliberately brief and keeps canonical identifiers and
reason codes available without exposing protocol internals.
