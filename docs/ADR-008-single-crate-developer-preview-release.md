# ADR-008: Release the first developer preview as one crate

## Status

Accepted

## Context

The management foundation currently builds one library and three related
binaries from one package. Splitting types, policy evaluation, controller,
adapter API and CLI into separate release trains would add coordination before
those components have independent owners or cadences.

## Decision

Prepare the `0.1` developer preview as the existing
`iicp-management-core` crate. It contains the library, operator CLI,
domain-local controller and conformance runner. Keep their semantic boundaries
documented and tested so they can be split later without redefining contracts.

The release lane is local-first and guarded. Hosted pull-request CI tests the
source but never publishes. Publication and deployment require separate
maintainer decisions.

## Consequences

- One locked artifact can prove installability and the complete local workflow.
- Operators do not need to coordinate several preview package versions.
- The package name emphasizes the public foundation rather than a management
  product.
- A later split remains necessary if ownership, security cadence or stable
  compatibility boundaries diverge.
