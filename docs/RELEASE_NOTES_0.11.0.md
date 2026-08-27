# IICP Management Foundation 0.11.0 candidate

This unpublished developer-preview candidate connects an active Management
policy generation to the Rust client's existing routing-policy boundary. It
does not add a second discovery, ranking, retry or dispatch implementation.

`RoutingEnforcementProjectionV1` intersects the caller's constraints with the
supported active Management policy and binds the result to the policy
generation, effective-policy digest and a fresh content-free candidate
snapshot. `ManagedIicpClient` revalidates that projection immediately before
delegating to `IicpClient`.

The projection fails closed when policy or candidate evidence is stale,
unresolved, malformed, unsupported, tampered with or outside the projected
candidate set. The real-client tests cover all built-in strategies and an
external ranker. When permitted candidate A is unavailable, region-prohibited
B and approval-prohibited C receive no dispatch.

The portable artifact remains
`iicp.management-routing-enforcement.v1`. Version 0.11 adds no protocol wire
field, Directory record, remote management service, activation authority or
production deployment. The process-local tests are not yet the disposable
PHP/Rust Directory qualification proof or representative administrator
evidence. Publication, deployment, adoption and a coordinated stability label
remain separate decisions.
