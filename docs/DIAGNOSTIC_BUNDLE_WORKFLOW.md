# Portable diagnostic bundle workflow

The diagnostic workflow turns explicit local management evidence into one content-minimized JSON record. It does not contact a Directory, controller endpoint or managed target.

## Create a bundle

```bash
iicp-management diagnostics create assessment.json \
  --controller controller.db \
  --adapter adapter-inspection.json \
  --profile management-profile.json \
  --requirement management-profile-requirement.json \
  --rollout-status rollout-status.json \
  --output diagnostic.json
```

Only the assessment and output path are required. Missing optional inputs are recorded as `NOT_AVAILABLE`. If an optional input is supplied but cannot be parsed, validated or shown to be fresh, creation stops without writing the requested output. The output file is created with owner-only permissions on Unix and is never overwritten implicitly.

## Inspect and verify

```bash
iicp-management diagnostics show diagnostic.json
iicp-management --json diagnostics show diagnostic.json
iicp-management diagnostics verify diagnostic.json
```

The brief view shows the overall state, the evidence condition behind each warning or failure, and bounded safe next actions. JSON is the stable automation form. Verification recalculates the canonical digest and checks freshness, structure, derived overall state and next actions.

## Privacy and authority boundary

The bundle contains counts, states, reason codes and digests. It omits raw policies, desired configuration, prompts, responses, credentials, request and target identifiers, and private topology. Review the bundle before sending it outside its administrative domain: even minimized operational evidence may reveal component versions, timing and aggregate state.

`payload_digest` detects modification; it is not a signature. A bundle cannot authorize apply, recovery, rollout, reconciliation or any other mutation, and it is not proof that a remote target converged. Source receipts retain their own authority and evidentiary meaning.

## Runtime-aware bundle (v2)

Provide both runtime flags to bind a local runtime-health snapshot into a minimized version 2 bundle:

```bash
iicp-management diagnostics create assessment.json \
  --runtime-health runtime-health.json \
  --runtime-target node:local \
  --output diagnostic.json
```

Use `-` for bounded stdin input. Omitting both runtime flags retains the historical version 1 output. Supplying only one flag fails closed. The target is used only while projecting the source snapshot and is not retained in the diagnostic bundle.
