# Policy template and impact-preview workflow

This workflow demonstrates the public, non-authorizing management path. It does
not install a component, activate policy or change a target.

## Inspect and render

```bash
iicp-management template list
iicp-management template show eu-processing
iicp-management template render examples/templates/render-request.json
```

The rendered result contains an ordinary stored policy revision and application
binding. Review or edit those canonical objects before submitting them to the
existing validation, simulation, planning and authorization lifecycle.

## Preview an evidence-bound change

```bash
iicp-management --json impact preview examples/templates/impact-request.json
```

The example shows a currently allowed US candidate becoming denied by an EU
processing policy. It also reports the explicitly missing fallback. Operational
metrics remain `NOT_AVAILABLE` because the fixture supplies no fresh metric
evidence.

## Run the disposable sequence

```bash
iicp-management bootstrap sandbox
```

The sandbox assesses a synthetic environment, renders the high-availability
template, previews impact, simulates the policy decision and creates a plan. It
stops before authorization. Its friction evidence is labelled
`project_rehearsal` with `representative=false`; it cannot satisfy an
administrator usability gate.
