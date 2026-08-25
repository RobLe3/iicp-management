# Management Foundation 0.6 developer preview

This preview is for local evaluation of the public IICP management contracts,
planner, controller and conformance runner. It does not install a remote
administration service, change an IICP Directory, start a system service or
authorize production use.

## Five-minute evaluation

Use a reviewed source checkout and the committed dependency graph:

```bash
cargo install --locked --path .
iicp-management --json profile verify examples/finance/management-profile.json
iicp-management --json plan \
  examples/finance/desired-state.json \
  examples/finance/accepted-state.json
iicp-management bootstrap sandbox
iicp-management-conformance
```

The first two commands return JSON. `bootstrap sandbox` creates a disposable
local example and prints its location. The conformance runner exits `0` only
when every bundled case passes.

The profile describes compatibility; it does not establish trust or grant
authority. A plan is a deterministic proposal; it does not apply a change.
Only the owner-protected local controller can accept an exactly authorized
operation, and target execution requires a separately configured adapter.

## Packaged crate

After a reviewed release is published, install the exact version with its
published lockfile:

```bash
cargo install iicp-management-core --version 0.6.0 --locked
```

Do not remove `--locked` if installation fails. A locked failure means the
approved dependency graph could not be reproduced and should be investigated.
The 0.6 readiness process tests the packaged `.crate`; it does not authorize
publication by itself.

## Offline bundle

The local readiness lane creates an integrity-listed offline bundle containing
the packaged source and vendored dependencies. Transfer both the bundle and
`release-manifest.json`, verify the recorded SHA-256 digest, then install from
the extracted directory:

```bash
tar -xzf iicp-management-core-0.6.0-offline.tar.gz
cd iicp-management-core-0.6.0
CARGO_HOME="$(mktemp -d)" cargo install --offline --locked --path .
iicp-management-conformance
```

The bundle is suitable for evaluation in an isolated environment. It is not a
signed binary distribution and does not remove the need to authenticate its
transfer source.

## Release validation

The `0.6.0` package is a developer-preview release candidate until the guarded
publisher verifies crates.io and the immutable release assets. Release
preparation from a clean, reviewed checkout uses `scripts/release_readiness.sh`; do not
substitute an unlocked registry install. The readiness lane exercises the
administrator trial workflow through both the packaged crate and vendored
offline bundle and validates the generated release manifest against the
packaged schema.

## Recovery and removal

The evaluation commands do not register a service. Remove the installed
binaries with:

```bash
cargo uninstall iicp-management-core
```

Delete only sandbox paths you created. Controller databases contain local
management evidence and should be retained or archived according to operator
policy. Never treat deletion of a controller database as rollback of a target.

## Compatibility and limits

See [`COMPATIBILITY.md`](../COMPATIBILITY.md) for the supported Rust baseline,
contract versioning and non-goals. This developer preview has no stability,
deployment or adoption claim. Publication, installation, deployment and
operational adoption are separate evidence states.
