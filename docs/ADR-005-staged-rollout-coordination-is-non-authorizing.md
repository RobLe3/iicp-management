# ADR-005: Staged rollout coordination is non-authorizing

**Status:** accepted  
**Date:** 2026-08-25

## Context

A change that is safe for one target can still fail across a fleet. Operators need a canary, ordered batches, durable progress, explicit retries and an honest view of partial convergence. A coordinator must not become a new authority above domain-local controllers.

## Decision

A rollout manifest binds an immutable target set to one administrative domain and audience. Batch zero contains exactly one required canary. Each target carries an exact, independently signed `LocalApplyGateV1`; the rollout manifest explicitly grants no execution authority. Execution remains at the target's existing owner-protected local controller endpoint.

The reference executor is sequential. It persists run and target state in a separate SQLite ledger, resumes an interrupted in-flight target through the controller's existing idempotent execution journal, and advances only after every target in the current batch reaches a terminal state. The default failure posture is stop and hold. Retry is explicit and is limited to deferred outcomes.

Partial convergence is reported, never relabelled as success. Accepting it requires a signed, version-bound administrative artifact. Acceptance records disposition only: it does not change target state, retry work, compensate earlier operations or authorize later execution.

## Consequences

- A fleet rollout cannot widen any target's pre-existing authorization.
- Canary failure prevents later batches.
- Durable progress and exact receipt bindings make restart and audit behavior deterministic.
- V1 does not provide parallel execution, global transactions, automatic compensation, cross-domain rollout or continuous remediation.
- No deployment follows from this decision.
