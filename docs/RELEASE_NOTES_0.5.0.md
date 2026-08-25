# IICP Management Foundation 0.5.0

This developer preview adds operator-facing application-policy and routing
inspection. Both commands project existing typed policy-lifecycle state. They
do not mutate accepted or target state, choose a fixed provider, or add a
management service.

The release also repairs the release-manifest contract. The generated manifest
must validate against the packaged schema, match the Cargo version and name the
exact crate and offline bundle for that version.

Install the exact published release with its lockfile:

```bash
cargo install iicp-management-core --version 0.5.0 --locked
```

Publication is not deployment. This package does not install or start a remote
controller, change a Directory, or establish representative administrator
adoption.
