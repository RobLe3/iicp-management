# Inspect local runtime health

The Management Foundation can turn an existing Rust node runtime-health snapshot
into a compact, non-authorizing operator view.

```bash
iicp-management show runtime-health runtime-health.json --target node:local --brief
```

For automation, place the global JSON flag before the command:

```bash
iicp-management --json show runtime-health runtime-health.json --target node:local
```

A local pipeline can use standard input:

```bash
cat runtime-health.json | iicp-management --json show runtime-health - --target node:local
```

The command reads only the supplied file or standard input. It does not find a
process, contact a node, query a Directory or change service state. The output
removes PID and process epoch, binds the source through a SHA-256 digest, marks
stale evidence as `unknown`, and carries `authorizes_mutation: false`.

Input is limited to 1 MiB. Unsupported schema versions, malformed JSON, future
observation timestamps and secret-like fields are rejected. A rejected or stale
snapshot is not replaced by log freshness or another inferred healthy signal.

Runtime state answers what the node reported. Any restart, configuration update
or recovery still requires the existing domain-local authorization and exact-plan
workflow.

The same explicit snapshot can accompany a canonical runtime configuration
during bootstrap assessment:

```bash
iicp-management --json bootstrap from-runtime-config runtime-config.json \
  --resource-id runtime:local \
  --runtime-health runtime-health.json \
  --runtime-target runtime:local > assessment.json
```

The target must match the managed resource. The resulting assessment contains
the minimized runtime projection, not the raw process identifier or process
epoch, and remains non-authorizing.
