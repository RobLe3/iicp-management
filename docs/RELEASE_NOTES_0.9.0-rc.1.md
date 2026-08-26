# Management Foundation 0.9.0-rc.1

This unpublished candidate adds a direct path from an existing canonical IICP
runtime configuration to the Management Foundation's bootstrap assessment.

```bash
iicp-management --json bootstrap from-runtime-config runtime-config.json \
  --resource-id runtime:local > assessment.json
```

Optional runtime-health evidence is supplied explicitly and projected through
the existing content-minimized runtime observation. The command does not execute
another program, inspect node identity files, contact a Directory, establish
trust, activate state or manage a service.

The candidate preserves all published 0.8 contract generations. It is intended
for locked packaged and offline-install validation before any separate stable
release decision. It is not tagged, published or deployed.
