# IICP Management Foundation 0.1.0

This is the first developer preview of the public, implementation-neutral IICP
management foundation. It includes typed policy and desired-state contracts, a
deterministic planner, a domain-local controller, bounded adapters, an operator
CLI and the project conformance runner.

The release is intended for local evaluation and independent contract review.
It does not provide a remote administration service, a production service
installer or authority over an IICP Directory. Installing the crate does not
deploy or activate a controller.

## Install

```bash
cargo install iicp-management-core --version 0.1.0 --locked
iicp-management-conformance
```

The GitHub release also contains the exact packaged crate, a vendored offline
bundle and a manifest binding those artifacts and the public contract schemas
to the release commit. The manifest is integrity evidence, not a signature or
deployment authorization.

See `docs/DEVELOPER_PREVIEW_INSTALLATION.md` and `COMPATIBILITY.md` for the
supported evaluation workflow and compatibility boundaries.
