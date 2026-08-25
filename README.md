# IICP Management Foundation

This repository contains implementation-neutral management contracts, a
deterministic Rust evaluator and planner, and project-owned conformance
fixtures for IICP domains. It is Apache-2.0 software and is separate from the
IICP wire protocol and from optional management clients and operator interfaces.

The foundation is an early development surface. It includes a headless
domain-local controller and bounded synthetic and runtime-configuration
adapters. It does not include a remote administration service, service restart
authority or production deployment.

For a bounded five-minute evaluation, packaged-crate rules and the offline
bundle procedure, see the
[`0.1 developer-preview installation guide`](docs/DEVELOPER_PREVIEW_INSTALLATION.md).

## State model

The contracts keep four states distinct:

- **desired state** is a portable proposal;
- **accepted state** is the generation authorized by the domain-local authority;
- **observed state** is what a target reports or a verifier measures;
- **effective state** is the evidence-backed convergence result.

Plans are deterministic functions of a validated desired-state bundle and an
accepted-state snapshot. Digests use RFC 8785 JSON Canonicalization Scheme
bytes. Approval binds the exact bundle digest, plan digest, audience and
expected generation. Portable artifacts contain secret references rather than
secret values.

## Typed policy evaluator

The `typed-v0` evaluator has no dependency on Cedar, CEL, OPA or another policy
engine. It keeps eligibility separate from ranking, applies explicit deny
precedence and returns stable reason codes. Unknown or stale evidence, adapter
failures and missing apply authority fail closed.

The policy-lifecycle v1 contracts add immutable policy revisions, policy sets,
one-to-many application bindings and generation-bound activation. Stored and
active policy remain separate. Effective policy, simulation and decision
explanation are deterministic projections rather than editable policy state.
CLI, API, automation and optional graphical clients consume the same typed
contracts; command text is not canonical state.

The profile bounds serialized policy and context sizes, rule and syntax-tree
size, expression and named-reference depth, collection size, deterministic
fuel and host execution time. An implementation may advertise lower local
limits but cannot silently raise the profile maximum. Named rules are resolved
with cycle detection before evaluation.

## Test and conformance commands

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo run --locked --bin iicp-management-conformance
python3 tools/run_management_conformance.py fixtures/management-portable-conformance-v1.json
python3 tools/run_policy_lifecycle_conformance.py fixtures/policy-lifecycle-conformance-v1.json
python3 tools/run_progressive_authority_conformance.py fixtures/progressive-authority-conformance-v1.json
python3 tools/run_adapter_inspection_conformance.py fixtures/adapter-inspection-conformance-v1.json
```

The conformance runner accepts an optional fixture path:

```bash
cargo run --locked --bin iicp-management-conformance -- path/to/fixture.json
```

It writes a deterministic JSON report. Exit status `0` means every case passed,
`1` means at least one result differed and `2` means the input or invocation was
invalid. The built-in report is project evidence. It is not independent
interoperability evidence.

See [CONFORMANCE.md](CONFORMANCE.md) for the language-neutral EM-1 fixture pack,
clean-room instructions and result-bundle requirements.

The next foundation layer provides a headless domain-local controller and
capability-scoped adapters. See [LOCAL_AUTHORITY.md](LOCAL_AUTHORITY.md) for its
authority, IPC, persistence and deployment boundaries.

## Read-only operator CLI

The `iicp-management` binary projects the typed contracts into a compact
operator surface. It validates and plans desired state, shows policy inventory
and effective policy, simulates policy changes, explains decisions, verifies
receipts and inspects a local controller database without opening it for
writing. Human-readable output is the default; place `--json` before the
command for deterministic automation output. Exported controller snapshots are
local evidence projections and explicitly carry no mutation authority.

```bash
cargo run --locked --bin iicp-management -- validate desired-state.json
cargo run --locked --bin iicp-management -- --json plan desired-state.json accepted-state.json
cargo run --locked --bin iicp-management -- show effective-policy workspace.json facts.json binding:example
cargo run --locked --bin iicp-management -- controller status controller.db
```

See [`examples/finance`](examples/finance/README.md) for a complete disposable
workflow. These commands do not authorize or apply changes. Command text and
formatted output are projections; JSON management artifacts remain canonical.

Adapter hosts can emit `adapter-inspection-v1` evidence containing bounded
capabilities, observation digests, generations and convergence receipts. The
CLI can combine this artifact with the controller's read-only snapshot:

```bash
iicp-management controller status controller.db adapter-inspection.json
iicp-management evidence export controller.db adapter-inspection.json
```

Missing adapter evidence remains `not_reported`. Observation without a receipt
is not called convergence, generation disagreement remains visible, and the
combined projection never carries apply authority.

## Exact local plan submission

`submit-plan` is the first deliberately state-changing operator command. It
sends a pre-signed `iicp.management-plan-submission.v1` artifact to the existing
owner-protected local controller endpoint:

```bash
iicp-management --json submit-plan \
  /run/user/$(id -u)/iicp-management.sock submission.json
```

The CLI does not load or create a signing key. The submission binds the exact
canonical plan digest, desired-state bundle digest, resource identifiers,
audience, administrative domain, action, generation, expiry and nonce. The
controller rechecks those bindings before accepting the next generation.

An accepted receipt always reports `target_effect: not_attempted` and
`convergence: not_evaluated`. Acceptance records controller state only; it does
not invoke an adapter, alter a target, restart a service or prove convergence.
Exit status `0` means accepted, `3` means rejected and `5` means deferred.
Deterministic input or authorization failures are never converted into a
deferred result.

## Apply preview and progressive authority

An apply request remains separate from plan acceptance and target execution.
The `iicp.management-apply-gate.v1` artifact binds one accepted plan and one
capability-scoped operation to progressive-authority evidence and a separately
signed authorization record. The authorization signature covers the exact
plan, operation, policy generation, facts, audience, domain, mode and expiry.

Preview is always non-mutating:

```bash
iicp-management preview-apply apply-request.json
```

Confirmation mode requires the exact operation identifier. There is no implicit
yes flag:

```bash
iicp-management request-apply /run/user/$(id -u)/iicp-management.sock \
  apply-request.json --confirm operation:finance
```

`automatic_within_policy` is the only non-interactive mode and requires the
same signed authorization artifact:

```bash
iicp-management request-apply /run/user/$(id -u)/iicp-management.sock \
  apply-request.json --non-interactive
```

Observation and recommendation evidence cannot request apply. A successful
request records controller authorization and returns the operation and authority
digests, but still reports `target_effect: not_attempted` and
`convergence: not_evaluated`. Adapter execution belongs to a later lifecycle
stage.

## Staged multi-target convergence

The rollout contract coordinates exact local apply gates across an immutable target set. Batch zero is a required canary; later batches advance only from durable per-target receipts. The coordinator grants no target authority, retries are explicit, and partial convergence remains visible even when an operator signs an acceptance record.

See [the staged rollout runbook](docs/STAGED_ROLLOUT_RUNBOOK.md) and [ADR-005](docs/ADR-005-staged-rollout-coordination-is-non-authorizing.md). No production deployment is included.

## Drift detection and bounded reconciliation

Terminal rollouts can import fresh adapter-inspection evidence and compare it with the last verified target receipt. Detection is non-authorizing, missing evidence remains unknown, and only explicitly classified safe metadata or capability/runtime drift can produce a bounded proposal. Execution still requires a fresh exact local apply gate. See [the runbook](docs/DRIFT_AND_RECONCILIATION_RUNBOOK.md) and [ADR-006](docs/ADR-006-drift-detection-default-reconciliation-bounded.md).

## Authority boundary

The contracts do not grant management authority. A future domain-local
controller must authenticate and authorize an exact plan before any adapter can
apply it. IICP membership, discovery, dispatch tickets and provider reputation
do not substitute for management authorization.

Other services may consume these contracts but cannot widen domain-local policy
or become undeclared IICP protocol authority. Product workflows, analytics, IAM
integrations, managed operations and product-specific interfaces remain outside
this repository.

## Direct-controller compatibility profile

The controller exposes a deterministic, non-authorizing profile through its
owner-protected local transport. Clients can validate a profile, calculate the
required compatibility intersection or query the configured controller:

```bash
iicp-management profile verify profile.json
iicp-management profile intersect profile.json requirement.json
iicp-management profile controller /run/user/$(id -u)/iicp-management.sock
```

The profile advertises only configured and compiled behavior. It does not grant
trust or permission to apply a change, and it does not add a Directory field or
network administration endpoint. See
[`docs/MANAGEMENT_PROFILE.md`](docs/MANAGEMENT_PROFILE.md) and
[`ADR-007`](docs/ADR-007-management-profile-is-non-authorizing.md).

## Progressive adoption

Observation, recommendation and execution are separate management claims.
Shadow evaluation must not mutate accepted or target state, and a recommendation
does not carry apply authority. See
[`docs/ADR-002-progressive-operational-authority.md`](docs/ADR-002-progressive-operational-authority.md).
The `progressive-authority-v1` contract records the operating mode, policy
generation and evidence provenance. `may_request_apply` means only that the
projection has the required plan, authorization evidence and satisfied policy
boundary; the domain-local controller still makes the apply decision.

### Authorized local execution

Execution is a second, explicit step. Start the controller with one narrowly
configured target adapter, authorize the exact apply gate, and then submit that
same gate for execution:

```bash
iicp-management-controller serve-executor \
  /run/user/$(id -u)/iicp-management.sock controller.db operator.pub \
  controller:local domain:local runtime-config-v1 runtime:primary runtime.json

iicp-management request-apply /run/user/$(id -u)/iicp-management.sock \
  apply-request.json --confirm operation:finance

iicp-management execute-apply /run/user/$(id -u)/iicp-management.sock \
  apply-request.json --confirm operation:finance
```

The controller persists the exact operation and authority-context digests when
it authorizes the request. Execution resumes only that stored authorization;
it does not consume the nonce or advance controller generation again. Controller
generation and target generation are separate concurrency domains.

Every attempt produces separate controller-authorization, adapter and
independent verification evidence. A timeout, I/O interruption or unknown
adapter outcome is observed before any retry decision and is reported as
`deferred`; this slice never retries an apply automatically. Full crash recovery,
rollback orchestration and fleet deployment remain separate later milestones.

### Truthful recovery

Recovery requires a new signed authorization at the current controller and
target generations. `preview-recovery`, `request-recovery`, and
`execute-recovery` use `iicp.management-local-recovery.v1`; an earlier apply
authorization cannot be reused. Exact reversal is available only when the
selected adapter retained bounded prior-state material and an independent
readback verifies the previous digest.

The contract also names compensation and safing without pretending they are
generic rollback. An adapter that has no explicit implementation returns a
typed failure and a safe next action. Receipts distinguish `reversed`,
`compensated`, `safed`, `partially_recovered`, `deferred`, and `failed`.
Externally visible effects remain part of history even after compensation.

For the disposable restart and recovery rehearsal, see
[`docs/AUTHORIZED_LOCAL_APPLY_RUNBOOK.md`](docs/AUTHORIZED_LOCAL_APPLY_RUNBOOK.md).

## Portable bootstrap and diagnostics

Bootstrap assessment is deliberately non-authorizing. It records fresh
observations, recommendations and decisions that still require an operator;
discovered components remain candidates until their evidence is verified.

```bash
iicp-management bootstrap assess assessment.json
iicp-management doctor assessment.json controller.db adapter-inspection.json
iicp-management bootstrap proposal assessment.json operator:local controller:local 0
iicp-management bootstrap import desired-state.json
iicp-management bootstrap sandbox
```

`doctor` reports `PASS`, `WARN`, `FAIL` and `NOT_AVAILABLE` from explicit local
inputs. Import and proposal creation do not activate state. The sandbox uses
disposable synthetic evidence and labels its friction record as a project
rehearsal, not representative administrator evidence.

## Policy templates and impact preview

Reference templates are inputs to the existing policy lifecycle, not a second
policy engine. List or inspect the catalog, then render an explicit request:

```bash
iicp-management template list
iicp-management template show eu-processing
iicp-management template render render-request.json
iicp-management impact preview impact-request.json
```

The initial catalog contains `internal-only`, `eu-processing`,
`maximum-privacy` and `high-availability`. Rendering produces normal policy
revision and application-binding objects with `authorizes_activation=false`.
Impact preview evaluates only supplied candidate facts. Cost, latency, quality
and capacity are reported as `NOT_AVAILABLE` unless the request supplies fresh,
integrity-bound observations. Neither operation changes accepted or target
state.

A copy-and-paste walkthrough and deterministic fixtures are available in
[`docs/POLICY_TEMPLATE_WORKFLOW.md`](docs/POLICY_TEMPLATE_WORKFLOW.md).
