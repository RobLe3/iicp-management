# Changelog

## 0.10.1 — 2026-08-26 developer preview

- Pin the locked ICU4X transitive dependency set to versions that compile with
  the declared Rust 1.86 minimum.
- Add an exact declared-toolchain locked build to release readiness so newer
  host compilers cannot conceal future MSRV drift.
- Create Unix controller sockets with owner-only permissions at bind time
  instead of relying on a bind-then-chmod sequence.
- Preserve the 0.10.0 contracts, first-run behavior and non-authorizing
  boundaries without a wire or serialized-behavior change.

## 0.10.0 — 2026-08-26 developer preview

- Compose runtime configuration, bounded runtime-health evidence, diagnostics and
  a desired-state proposal into one non-authorizing bootstrap workflow.
- Add the portable bootstrap-workflow contract, fixtures and standard-library
  conformance checker.
- Add `bootstrap prepare` plus truthful CLI version reporting without adding
  discovery, activation, service control or network side effects.
- Promote the unchanged `0.10.0-rc.1` behavior after an isolated packaged-crate
  project rehearsal completed with zero release blockers, zero manual secret
  transfers and no Directory, production-target or service contact.

## 0.9.0 — 2026-08-26 developer preview

- Convert an explicit canonical runtime configuration into the existing
  non-authorizing bootstrap assessment and desired-state proposal path.
- Optionally bind content-minimized runtime-health evidence to the same managed
  resource without executing another process or contacting a Directory.
- Preserve the published 0.8 contracts and keep publication, deployment and
  representative administrator evidence as separate gates.

## 0.8.0 — 2026-08-25 developer preview

- Add diagnostic bundle v2 with content-minimized runtime-health evidence while preserving v1.
- Extend diagnostic creation, verification, display and shell completion with explicit runtime inputs.
- Bind runtime freshness, state counts and truthful readiness outcomes without target identity or mutation authority.

## 0.7.0 — 2026-08-25 developer preview

- Add a content-minimized, freshness-bounded projection of local Rust node runtime-health v1 evidence.
- Add read-only file/stdin CLI inspection, typed JSON output and shell completion.
- Reject unsupported, future-dated, sensitive, malformed and oversized input without an inferred healthy fallback.
- Keep runtime observation separate from wire semantics and lifecycle authority.

## 0.6.0 — 2026-08-25 developer preview

- Add bounded candidate-evidence and resolution-inspection contracts.
- Classify candidates as eligible, ineligible or unresolved without ranking, selection, dispatch or mutation.
- Extend `show routing` and shell completion with candidate-aware inspection while retaining the 0.5 facts-based projection.
- Add portable Rust/Python classification fixtures, schema validation and operator examples.

## 0.5.0 — 2026-08-25 developer preview

- Expose application-policy briefs and dynamic, evidence-bound routing summaries through the operator CLI.
- Extend static shell completion and portable policy-lifecycle projections for the new inspection commands.
- Validate generated release manifests against the packaged schema and current Cargo version.
- Reconcile the developer-preview installation guide with the current release line.

## 0.4.0 — 2026-08-25 developer preview

- Add privacy-bounded administrator trial-session and friction-evidence v2 contracts.
- Add atomic trial start, event, finish, verify and same-workflow summary commands.
- Preserve failures, abandoned runs and assistance without granting release or mutation authority.
- Retain version 1 friction evidence and the Management 0.3.0 sandbox unchanged.

## 0.3.0 — 2026-08-25 developer preview

- Adds a one-command, authorized local management exercise with bounded
  project-rehearsal evidence.
- Adds deterministic verification-failure and interrupted-resume scenarios;
  uncertain mutations are never retried automatically.
- Documents clean and offline local installation without publishing or
  deploying the candidate.

This project follows semantic versioning for published packages. Contracts and
fixtures retain their own explicit schema and profile generations.

## 0.2.0 — 2026-08-25 developer preview

- Portable, content-minimized diagnostic bundle creation, verification and operator inspection.

The diagnostic bundle is a non-authorizing projection of explicit local
evidence. It does not contain raw policy, desired state, prompts, responses,
credentials, request or target identifiers, or private topology. Publication
does not deploy a management service or establish representative adoption.

## 0.1.0 — 2026-08-25 developer preview

- Portable desired-state, planning, approval, receipt and policy contracts.
- Deterministic typed policy lifecycle, simulation and decision explanation.
- Domain-local controller with owner-protected IPC and capability-scoped
  synthetic and runtime-configuration adapters.
- Exact local apply, independent verification and truthful recovery evidence.
- Portable bootstrap, diagnostics, templates and impact preview.
- Staged multi-target convergence and bounded drift reconciliation.
- Direct-controller management profile and compatibility intersection.

This developer preview is published. It provides no remote administration
service, production service installer, Directory integration or deployment.
