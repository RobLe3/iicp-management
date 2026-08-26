# Management Foundation 0.10.0-rc.1

This unpublished release candidate adds one portable preparation step for an
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

The candidate adds the versioned `iicp.management-bootstrap-workflow.v1`
contract, portable positive and negative fixtures, a standard-library checker,
static shell completion and `iicp-management --version`.

This candidate is prepared for local and offline verification only. It is not
published or deployed, and its project-owned test evidence is not representative
administrator adoption evidence.
