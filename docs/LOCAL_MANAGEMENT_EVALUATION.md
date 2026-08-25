# Local management evaluation

This exercise demonstrates the public, typed IICP management path on one
machine. It is intended for developers and evaluators who want to inspect the
authority and recovery behavior before connecting a real adapter.

## Run from a checkout

```bash
cargo build --locked --release
./target/release/iicp-management bootstrap sandbox \
  --exercise authorized-local
```

For machine-readable output:

```bash
./target/release/iicp-management --json bootstrap sandbox \
  --exercise authorized-local
```

The command uses an ephemeral controller database and the in-memory synthetic
adapter. It performs no network request, does not install or restart a service,
and removes its temporary state when it exits.

## Inspect failure handling

```bash
./target/release/iicp-management --json bootstrap sandbox \
  --exercise authorized-local --scenario verification-failure

./target/release/iicp-management --json bootstrap sandbox \
  --exercise authorized-local --scenario interrupted-resume
```

The verification-failure scenario cannot report success. The interrupted-resume
scenario observes the target state before making a recovery decision; it does
not repeat the mutation. Both return separate lifecycle and verification
evidence with `automatic_retry_permitted` set to `false`.

## Install the packaged candidate locally

Create and inspect the package before installing it:

```bash
cargo package --locked --allow-dirty
cargo install --locked --path . --root /tmp/iicp-management-evaluation
/tmp/iicp-management-evaluation/bin/iicp-management --json \
  bootstrap sandbox --exercise authorized-local
```

An offline installation is possible after Cargo has fetched the locked
dependency set:

```bash
cargo install --locked --offline --path . \
  --root /tmp/iicp-management-evaluation-offline
```

The package is a developer-preview candidate. It is not published or deployed
by this procedure.

## Reading the evidence

Every exercise result states:

- `evidence_class: project_rehearsal`
- `representative: false`
- `local_only: true`
- `activated_external_state: false`

The phases describe the intended end-to-end management sequence. The preview
shows the exact planned change. The lifecycle receipt distinguishes converged,
failed, deferred, and partially converged results, while the retry field records
whether human review is required.

Enterprise application and provider-routing scenes in project showcases explain
the architectural goal. They are not evidence that a named application or live
provider integration is present. A real integration requires its own adapter,
authorization, conformance, and deployment evidence.

## Cleanup

The command deletes its ephemeral state automatically. Remove the optional
installation roots when finished:

```bash
rm -rf /tmp/iicp-management-evaluation \
  /tmp/iicp-management-evaluation-offline
```
