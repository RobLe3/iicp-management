# Direct-controller management profile

The management profile describes what one exact domain-local controller can
understand and perform. It lets an operator or automation client check contract
compatibility before submitting a plan. Reading a profile does not authenticate
the caller, authorize a change or establish trust in a controller found through
discovery.

The current profile is available through the owner-protected local controller
transport. It reports the configured administrative domain, local binding,
schemas, canonicalization and signature algorithms, operations, installed
adapter resource kinds, evaluator profile, limits and evidence formats. The
controller derives these values from its active configuration and compiled
implementation; the query does not accept replacement claims from the caller.

```bash
iicp-management profile show profile.json
iicp-management profile verify profile.json
iicp-management profile intersect profile.json requirement.json
iicp-management profile controller /run/user/$(id -u)/iicp-management.sock
```

Use `--json` immediately after the command name for deterministic output.
An intersection is compatible only when every requested controller, domain,
binding, schema, algorithm, operation, resource kind and evaluator is present.
Unknown required or security-critical extensions fail closed. Optional
ignorable and negotiable extensions do not become requirements merely because
a future client knows about them.

## Authority boundary

The profile identifier `iicp.management-profile.v1` is a project-owned,
provisional contract identifier. It is not a registered IICP namespace or a
new Core opcode. The current implementation adds no network listener and loads
no controller signing key. Local transport ownership protects the query; the
profile itself is a canonical, digestible projection rather than a portable
claim of remote authenticity.

A future protected Directory record may reference a controller identity,
profile digest and endpoint after a concrete cross-boundary discovery need is
demonstrated. Such a record must remain optional and must never store policy,
grant management authority or make discovery equivalent to trust.

## Conformance

The portable fixture covers compatible, unsupported, expired and malformed
profiles:

```bash
cargo test --locked --test profile_conformance
python3 tools/run_management_profile_conformance.py \
  fixtures/management-profile-conformance-v1.json
```

Both runners are project evidence. Independent interoperability evidence
requires another implementation and remains a separate adoption gate.
