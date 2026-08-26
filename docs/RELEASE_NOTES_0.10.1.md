# IICP Management Foundation 0.10.1

This corrective developer-preview release makes the locked installation graph
honor the package's declared Rust 1.86 minimum. The 0.10.0 lockfile selected
ICU4X 2.3 packages whose metadata requires Rust 1.88; ordinary release checks
used a newer host compiler and did not expose the mismatch. Version 0.10.1 pins
the compatible ICU4X 2.2 set and verifies the complete locked graph with the
exact declared compiler during release readiness.

Unix controller sockets are also owner-only from the first observable
filesystem state. The publisher gate caught and removed the former
bind-then-chmod interval before publication.

There is no wire, contract or serialized-behavior change. The 0.10 first-run
workflow remains:

```bash
iicp-management --json bootstrap prepare runtime-config.json \
  --resource-id runtime:local \
  --operator-id operator:local \
  --controller-id controller:local \
  --controller-generation 0
```

The output remains `iicp.management-bootstrap-workflow.v1`, non-authorizing and
non-activating. This package does not contact a Directory, deploy a management
service, mutate a system service or establish representative administrator
evidence.
