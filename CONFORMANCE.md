# Portable management conformance

The EM-1 pack is a language-neutral contract for canonicalization, planning,
approval binding, receipt binding and convergence. It can be consumed without
reading the Rust implementation.

Run the reference, standard-library-only checker from a clean checkout:

```bash
python3 tools/run_management_conformance.py \
  fixtures/management-portable-conformance-v1.json \
  --output /tmp/iicp-management-report.json
```

Every case has a stable ID, explicit input and expected result. Implementers may
replace the checker with their own implementation and compare the same cases.
The digest operation uses RFC 8785 JCS followed by SHA-256. The supplied checker
supports the JSON value subset used by this pack; an implementation claiming
general JCS support must test against the complete RFC.

Result bundles use `contracts/management-conformance-result-v1.schema.json`.
Project-produced output is labelled `project-verified`. Independent evidence
must use `independent`, identify its public repository and exact commit, name
the runner version, and retain the per-case results. A report must not contain
credentials, secret values, task payloads, model output, private topology or
production identifiers.

These fixtures establish deterministic project evidence. They do not establish
independent interoperability, authorize target mutation, or describe a running
controller.

## Policy lifecycle profile

The policy-lifecycle pack covers versioned policy storage, application-binding
validation, deterministic composition, activation generations and simulation:

```bash
python3 tools/run_policy_lifecycle_conformance.py \
  fixtures/policy-lifecycle-conformance-v1.json \
  --output /tmp/iicp-policy-lifecycle-report.json
```

The reference checker deliberately implements only the expression subset used
by this pack. An independent implementation should consume the fixture contract
through its own lifecycle and evaluator code. Passing the reference checker is
project evidence, not independent interoperability or permission to activate a
policy in a deployed domain.
