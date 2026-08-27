# Portable management conformance

The EM-1 pack is a language-neutral contract for canonicalization, planning,
approval binding, receipt binding and convergence. It can be consumed without
reading the Rust implementation.

Run the reference, standard-library-only checker from a clean checkout:

```bash
python3 tools/run_management_conformance.py \
  fixtures/management-portable-conformance-v1.json \
  --output /tmp/iicp-management-report.json
```

Every case has a stable ID, explicit input and expected result. Implementers may
replace the checker with their own implementation and compare the same cases.
The digest operation uses RFC 8785 JCS followed by SHA-256. The supplied checker
supports the JSON value subset used by this pack; an implementation claiming
general JCS support must test against the complete RFC.

Result bundles use `contracts/management-conformance-result-v1.schema.json`.
Project-produced output is labelled `project-verified`. Independent evidence
must use `independent`, identify its public repository and exact commit, name
the runner version, and retain the per-case results. A report must not contain
credentials, secret values, task payloads, model output, private topology or
production identifiers.

These fixtures establish deterministic project evidence. They do not establish
independent interoperability, authorize target mutation, or describe a running
controller.

## Portable first-run preparation

The bootstrap-workflow pack verifies that explicit source evidence is bound to
the existing assessment, doctor and optional proposal contracts without
granting mutation authority:

```bash
python3 tools/run_bootstrap_workflow_conformance.py \
  fixtures/bootstrap-workflow-conformance-v1.json
cargo test --locked --test bootstrap_workflow_conformance
```

Ready assessments require a proposal; incomplete assessments prohibit one.
Source, proposal and authority tampering fail closed. Passing the pack does not
establish trust, activate state, contact a target or demonstrate representative
administrator usability.

## Policy lifecycle profile

The policy-lifecycle pack covers versioned policy storage, application-binding
validation, deterministic composition, activation generations, simulation and
the non-authorizing application-policy and resolution projections used by the
operator CLI:

```bash
python3 tools/run_policy_lifecycle_conformance.py \
  fixtures/policy-lifecycle-conformance-v1.json \
  --output /tmp/iicp-policy-lifecycle-report.json
```

The reference checker deliberately implements only the expression subset used
by this pack. An independent implementation should consume the fixture contract
through its own lifecycle and evaluator code. Passing the reference checker is
project evidence, not independent interoperability or permission to activate a
policy in a deployed domain.

## Progressive-authority profile

The progressive-authority pack separates observation and counterfactual
recommendation from confirmation and bounded automation:

```bash
python3 tools/run_progressive_authority_conformance.py \
  fixtures/progressive-authority-conformance-v1.json \
  --output /tmp/iicp-progressive-authority-report.json
```

The cases prove that observation and recommendation cannot request mutation,
that confirmation requires exact plan and authorization evidence, and that
automatic operation fails unless the policy boundary is satisfied. The
projection is not an execution receipt. Passing it grants no management
authority and does not prove that an apply occurred.

## Adapter inspection profile

The adapter-inspection pack covers bounded capability advertisement,
observation digests, freshness, convergence receipts, duplicate bindings and
unknown required extensions:

```bash
python3 tools/run_adapter_inspection_conformance.py \
  fixtures/adapter-inspection-conformance-v1.json
```

The artifact carries no raw target state and cannot authorize mutation. A
successful observation without an adapter receipt is not convergence. The Rust
and standard-library Python validators consume the same seven cases.

## Candidate-resolution inspection profile

The resolution-inspection pack binds the small, implementation-neutral
classification that combines a policy decision, candidate compatibility and
evidence freshness:

```bash
cargo test --locked --test resolution_inspection
python3 tools/run_resolution_inspection_conformance.py \
  fixtures/resolution-inspection-conformance-v1.json
```

Eligible candidates are not ranked or selected. Stale evidence and unknown
compatibility remain unresolved, and the resulting projection carries no
mutation authority. Passing the fixture does not authenticate the evidence
source, authorize dispatch or prove that any provider is reachable.

## Process-local routing enforcement

The routing-enforcement fixture and Rust integration tests cover the supported
lossless policy projection, contradictory-region refusal, unsupported policy,
generation and evidence-expiry checks, policy intersection, candidate-snapshot
binding and real `IicpClient` dispatch:

```bash
cargo test --locked --test routing_enforcement
```

The decisive failure case keeps the only permitted node unavailable while a
region-prohibited node and an identity-prohibited node remain reachable. Both
receive zero requests, and the client returns `IICP-POLICY-ROUTING` before an
external ranker or retry path can run. A separate case introduces an otherwise
permitted candidate outside the bound evidence snapshot and receives
`IICP-CANDIDATE-RANKER-REFUSED` before provider contact. This is project-owned,
process-local evidence; it is not representative administrator evidence or
independent interoperability proof.

## Direct-controller profile compatibility

The management-profile pack covers exact compatibility, unsupported
operations, unknown required security extensions, expired profiles, duplicate
claims and administrative-domain mismatch:

```bash
cargo test --locked --test profile_conformance
python3 tools/run_management_profile_conformance.py \
  fixtures/management-profile-conformance-v1.json
```

The profile is a compatibility projection. A passing result does not establish
controller identity, caller authorization or permission to mutate a target.


## Diagnostic evidence profile

The diagnostic packs cover complete and missing local evidence, partial
convergence, bundle tampering, sensitive content and unknown security-critical
extensions. Version 2 adds a minimized, target-independent runtime-health
projection while version 1 remains supported for bundles without runtime input:

```bash
cargo test --locked --test diagnostics --test diagnostics_v2_cli
python3 tools/run_diagnostic_v2_conformance.py \
  fixtures/diagnostic-bundle-conformance-v2.json
```

The portable v2 cases cover ready, degraded, not-ready, stale and unknown runtime
states, semantic tampering, target redaction, the legacy v1 path and unknown
schema rejection. The bundle is a content-minimized local projection. Passing a
fixture does not authenticate its creator, establish target convergence,
authorize mutation or constitute representative administrator evidence.

## Administrator trial evidence

`fixtures/administrator-trial-conformance-v2.json` records the bounded cases
for the version 2 trial-session and friction-evidence contracts. The Rust tests
execute those cases and validate serialized artifacts against
`contracts/administrator-trial-v2.schema.json`.

Passing this fixture proves only project conformance to the recorder contract.
It does not prove that a participant was independent, that an interface met a
time budget, or that a release gate was approved. Failed, abandoned and assisted
observations must remain in any reported aggregate.
