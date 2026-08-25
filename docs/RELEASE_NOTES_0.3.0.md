# IICP Management Foundation 0.3.0

This developer preview adds a one-command, end-to-end local evaluation of the
public IICP management contracts:

```bash
iicp-management bootstrap sandbox --exercise authorized-local
```

The exercise creates ephemeral controller state, previews one exact operation,
binds explicit local authorization, applies through the in-memory synthetic
adapter, independently verifies the result and records a lifecycle receipt.
Deterministic verification-failure and interrupted-resume scenarios demonstrate
that uncertain effects are observed rather than retried automatically.

Install the exact published dependency graph:

```bash
cargo install iicp-management-core --version 0.3.0 --locked
```

Every exercise result is labelled `project_rehearsal`, `representative=false`,
`local_only=true` and `activated_external_state=false`. It is not evidence of a
production application, provider integration or administrator trial.

The release assets include the packaged crate, a vendored offline source bundle
and an integrity manifest. Publication does not install a service, grant remote
authority, modify a Directory or authorize production deployment.
