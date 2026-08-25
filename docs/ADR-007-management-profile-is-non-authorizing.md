# ADR-007: The direct-controller management profile is non-authorizing

## Status

Accepted

## Context

Management clients need to determine whether an exact controller supports the
contracts required for an operation. Encoding this as an IICP workload intent,
placing policy in a Directory or relying on product-specific capability claims
would put management authority in the wrong layer.

## Decision

Define a versioned, canonical management profile in the public management
foundation. The profile is a read-only projection of configured and compiled
controller behavior. Compatibility intersection is deterministic and fails
closed for unknown required semantics. Profile discovery, validation and
compatibility never grant trust or mutation authority.

The first binding is owner-protected local IPC. Network discovery and Directory
advertisement remain later, separately reviewed work. The controller does not
load a private key merely to answer the local query.

## Consequences

- CLI, automation and future graphical clients can share one compatibility
  contract.
- Existing IICP workload behavior and Directory schemas remain unchanged.
- A stable profile digest can be referenced by later protected discovery.
- Local transport protection is not portable authenticity; any remote binding
  must define authentication, freshness, revocation and disclosure separately.
