# ADR-014: First-run preparation composes existing contracts

**Status:** accepted  
**Date:** 2026-08-26

## Context

An operator can already convert an explicit runtime configuration into a
bootstrap assessment, inspect readiness and create a desired-state proposal.
Running those steps separately is useful for debugging but adds avoidable work
to the ordinary local preparation path.

## Decision

Define `iicp.management-bootstrap-workflow.v1` as a typed envelope around the
existing assessment, doctor and desired-state contracts. The envelope records
the exact source digests. It includes a proposal only when the assessment is
ready for one.

Preparation is read-only and non-authorizing. It reads only explicit inputs,
does not execute another program, inspect identity material, contact a
Directory, activate state or manage a service. Private and local environments
retain their configured Directory boundary. The resulting proposal still
requires the existing domain-local authorization and application path.

## Consequences

- CLI, automation and future graphical clients can offer one preparation step
  without creating another policy or bootstrap model.
- Every component remains independently inspectable and portable.
- A successful preparation is not trust, authorization, activation,
  convergence or representative administrator evidence.
