# ADR-002: Progressive operating modes do not grant authority

**Status:** accepted  
**Date:** 2026-08-24

## Context

An organization may want to compare IICP policy decisions with existing traffic
before allowing management software to control anything. Observation,
recommendation and execution are different claims. Conflating them would let a
client presentation or deployment setting become an undeclared authorization
mechanism.

## Decision

The shared management surface distinguishes four operating modes:

- `OBSERVE` evaluates recorded facts without proposing or applying a change;
- `RECOMMEND` produces an evidence-bound alternative without mutation;
- `CONFIRM` requires an authorized principal to approve an exact plan;
- `AUTOMATIC_WITHIN_POLICY` may execute only inside previously authorized scope
  and remains subject to every domain-local controller check.

Mode is evidence, not authority. Observation and recommendation cannot mutate
desired, accepted or target state. They cannot manufacture execution receipts.
A change of mode requires the normal typed plan and authorization lifecycle.

Counterfactual decisions identify their fact snapshot, policy generation and
observation time. They are never presented as original task events.

## Consequences

- An implementation can support shadow and recommendation workflows without
  becoming part of the execution path.
- A graphical client, automation client or AI assistant cannot infer apply
  authority from its configured mode.
- Automatic optimization may select within an accepted policy boundary but
  cannot rewrite that boundary.
- A later interoperable contract can add mode and provenance fields without an
  IICP wire-protocol change.

## Follow-up boundary

The exact serialized projection and fixtures require separate review. Until
that work is accepted, implementations may experiment locally but cannot claim
portable management-profile conformance for these modes.
