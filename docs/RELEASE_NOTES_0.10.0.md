# Management Foundation 0.10.0

This developer-preview release adds one portable preparation step for an
existing canonical IICP runtime configuration:

```bash
iicp-management --json bootstrap prepare runtime-config.json \
  --resource-id runtime:local \
  --operator-id operator:local \
  --controller-id controller:local \
  --controller-generation 0
```

The result binds a non-authorizing bootstrap assessment, doctor report and,
when the input is ready, a desired-state proposal. Optional runtime-health
input is projected through the existing content-minimized contract. The
workflow does not discover peers, read identity or secret files, contact a
Directory, start a service, mutate a target or activate the proposal.

The release adds the versioned `iicp.management-bootstrap-workflow.v1`
contract, portable positive and negative fixtures, a standard-library checker,
static shell completion and `iicp-management --version`.

The exact packaged `0.10.0-rc.1` behavior passed an isolated first-run project
rehearsal before promotion. The rehearsal reported zero manual secret
transfers, zero release blockers, no Directory or production-target contact and
no service mutation. It remains project-owned evidence with
`representative=false`; publication does not deploy a service or establish
representative administrator adoption.
