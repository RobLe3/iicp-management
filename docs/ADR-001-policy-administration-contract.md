# ADR-001: Typed policy administration is the shared management surface

**Status:** accepted  
**Date:** 2026-08-24

## Context

Policy may be authored and inspected through a headless CLI, an API, automation
or an optional graphical client. If each interface defines its own lifecycle,
the same policy could validate, activate or explain differently depending on
the client used.

## Decision

IICP management defines versioned typed commands, queries and canonical policy
objects. Human commands and product interfaces are projections of those
contracts. Command text is not stored as policy truth.

The public lifecycle uses **Application Binding** for the association between an
upstream application and one or more policy revisions or sets. A user interface
may use `interface` as shorthand but cannot change the contract meaning.

Stored policy is distinct from active policy. Effective policy is computed from
the active binding, immutable revisions and an evidence snapshot; it is never a
second editable policy document. The domain-local controller remains the final
activation authority. Rollback is another authorized plan unless exact reversal
has been proved.

Upstream request connectors translate application requests and policy context.
Integration adapters apply bounded management operations to targets. Neither is
a policy engine.

`IIOS` remains a provisional internal and user-experience name. Public contracts
use the descriptive term **IICP Management Environment** and do not require a
specific CLI, graphical client or hosted service.

## Consequences

- CLI, API, automation and optional graphical clients can be compared using the
  same conformance fixtures.
- Canonical state remains implementation-neutral and content-addressable.
- A presentation layer cannot bypass controller authorization.
- A future policy language compiles to typed objects and transactions rather
  than CLI text.
- No IICP wire change or deployment follows from this decision.
