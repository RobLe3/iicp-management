# IICP Management Foundation 0.6.0

This developer preview adds candidate-aware, read-only resolution inspection.
A bounded inventory snapshot can be evaluated against an application binding,
and every candidate is reported as eligible, ineligible or unresolved. Expired
evidence remains unresolved. The command does not rank candidates, select a
provider, dispatch work or authorize mutation.

The release retains the 0.5 facts-based routing projection and adds a portable
classification fixture consumed by both Rust and a standard-library Python
checker. Discovery evidence does not establish trust, and eligibility does not
establish reachability or execution authority.

Install the exact published release with its lockfile:

```bash
cargo install iicp-management-core --version 0.6.0 --locked
```

Publication is not deployment. This package does not install or start a remote
controller, change a Directory, select an executor or establish representative
administrator adoption.
