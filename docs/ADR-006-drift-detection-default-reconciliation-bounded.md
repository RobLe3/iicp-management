# ADR-006: Drift detection is the default and reconciliation is bounded

**Status:** accepted

**Date:** 2026-08-25

## Context

Long-lived desired state can diverge after a rollout. An always-running remediation loop could repeat harmful operations, fight local operators or turn a coordinator into undeclared fleet authority.

## Decision

The reference implementation imports fresh, non-authorizing `AdapterInspectionV1` evidence and compares it with the last verified target receipt. Missing, stale or incomplete evidence is `unknown`, not converged. Drift is unclassified until an operator supplies a review classification.

Only safe-metadata and capability/runtime drift can enter the bounded reconciliation path. That path produces a non-authorizing proposal and requires a new exact `LocalApplyGateV1`, independently authorized by the domain-local controller. The gate binds the observed generation, desired digest, target, domain, audience and prior operation. Other drift classes remain report-only and require a separate recovery or governance decision.

## Consequences

- Detection can run without mutation authority.
- A proposal is not approval, execution or convergence evidence.
- Reconciliation remains one-shot, observable and idempotent through existing controller semantics.
- V1 has no scheduler, continuous remediation, cross-domain authority, global transaction or automatic compensation.
- No release or deployment follows from this decision.
