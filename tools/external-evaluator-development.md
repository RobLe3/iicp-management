# External evaluator development conformance

This optional experiment for [Management #168](https://github.com/RobLe3/iicp-management/issues/168) checks result composition without adopting an evaluator or modifying the Management profile or local-apply gate. It is separate from the contributor's reference implementation and from formal qualification.

Run the developer checks from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/run_external_evaluator_development_conformance.py
PYTHONDONTWRITEBYTECODE=1 python3 tools/test_external_evaluator_development_conformance.py
cargo test --offline --locked --test apply_gate experimental_external_allow_is_not_local_apply_authorization
```

The Python runner reuses the existing Management profile compatibility fixture.
Each experimental vector specifies its expected classification separately from
the runner. The v1 checker refuses a pack missing any required vector, so
dropping a negative case cannot turn an incomplete pack into a pass. The local
request and result checksums use sorted, compact ASCII JSON over the fixture's
string and integer value domain. They are not a wire
canonicalization or signature convention. The fixture uses an exclusive expiry
tick. Request binding, expiry, reason codes and evidence references remain
visible in the result; passing the checks does not authenticate those references.

Local and external permission can make a request eligible for further review.
Either denial blocks. An unresolved result with a recognized resolver and an
explicit deny-on-failure path is deferred, not allowed. The Rust test checks that
a genuine local gate still previews and that the external allow result cannot be
parsed as that gate or replace its typed authorization. No adapter is invoked.

The fixture lives under `tests/fixtures/` rather than the packaged `fixtures/`
tree. Neither the fixture nor this runner is part of the crate's published file
allowlist. This work adds no trust roots, replay handling, signature verification,
network calls, or authority transfer.
