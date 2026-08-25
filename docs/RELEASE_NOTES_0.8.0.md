# IICP Management Foundation 0.8.0

This developer-preview candidate adds runtime-aware diagnostic bundles without changing the existing version 1 diagnostic contract.

- `diagnostics create` emits version 1 unless both `--runtime-health` and `--runtime-target` are supplied.
- Runtime-aware bundles use `iicp.management-diagnostic-bundle.v2` and bind a sixth, freshness-bounded runtime artifact.
- Readiness, degradation, stale evidence and unknown state remain distinct and produce deterministic checks and safe actions.
- Diagnostic output omits the runtime target, process ID, process epoch, raw configuration, payloads and secret-like fields.
- `diagnostics show` and `diagnostics verify` accept versions 1 and 2 and reject unknown schema generations.

This candidate does not add a service, discovery, process control, remote administration, Directory changes, wire changes or deployment.
