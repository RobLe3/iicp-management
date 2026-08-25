# Administrator trial evidence workflow

This workflow records bounded usability evidence for one IICP management task.
It does not perform the task. Run the tested CLI, GUI or automation workflow
separately and record only the counted events and final machine-checkable result.

Use disposable or synthetic infrastructure. Obtain participant consent before
recording a representative or independent observation. Do not put names,
credentials, prompts, responses, raw policy, raw configuration or private
topology into any trial file.

## Record one observation

Start with a reviewed definition based on
`examples/trials/policy-simulation-definition.json`:

```bash
iicp-management trial start definition.json --output session.json
```

For every primary interaction, explicit input, manual secret transfer or
assistance event, create a small event file. Its timestamp must not precede the
session or the previous event.

```bash
iicp-management trial event session.json event.json
```

Finish with `success`, `failed` or `abandoned`. Success requires the SHA-256
digest of the machine-checkable result. Canonical references are optional but
must use disposable `test:` identifiers.

```bash
iicp-management trial finish session.json outcome.json \
  --output evidence.json
iicp-management trial verify evidence.json
```

The files are written atomically with owner-only permissions on Unix. If the
evidence file was written immediately before an interruption, repeating the
same finish operation verifies that exact file and finalizes the session. A
different existing output fails as a conflict. A finalized session cannot be
finished or extended again.

## Summarize comparable observations

Only observations for the same workflow can be summarized together:

```bash
iicp-management trial summarize evidence-*.json --output summary.json
```

The summary retains failures, abandoned runs and assistance. It reports the
completion rate, duration range and median, evidence-class counts and role
coverage. `numerical_threshold_met` means only that five declared
representative observations across three roles were supplied. It is not proof
of independence and never authorizes a release gate.

## Supported workflow identifiers

- `add_existing_intelligence_endpoint`
- `create_and_simulate_simple_policy`
- `create_restricted_trust_domain`
- `diagnose_failed_resolution`
- `restore_prior_policy_generation`
- `connect_new_site`

If the tested product cannot perform one of these workflows, record a failed or
abandoned result rather than inventing a successful capability.
