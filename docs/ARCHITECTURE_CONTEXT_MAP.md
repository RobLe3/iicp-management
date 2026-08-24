# Management architecture context map

This repository owns implementation-neutral management contracts and their
conformance evidence. It does not own the IICP wire protocol, a remote global
administrator, or product-specific operator experiences.

## Contexts and authority

| Context | Owns | Does not own |
| --- | --- | --- |
| Policy administration | Stored revisions, policy sets, application bindings, validation, simulation and generation-bound activation | Runtime eligibility decisions or protocol routing |
| Policy evaluation | Deterministic effective-policy evaluation, deny precedence and stable reason codes | Administrative approval or provider ranking |
| Domain-local authority | Authentication, authorization and acceptance of an exact plan within one domain | Authority over another domain or federation-wide superuser rights |
| Application binding | The association between an application attachment and one or more policy revisions | Upstream application behavior |
| Request connector | Translation of an upstream request into bounded IICP request and policy context | Policy definition or authority expansion |
| Integration adapter | Capability-scoped observation and application of an authorized local plan | Unbounded host control, restart authority or secret transport |
| Adoption projection | Evidence-bound observation, recommendation and friction measurements | Trust establishment, approval or mutation authority |

## State flow

```text
management client
      |
      v
validated management operation
      |
      v
domain-local controller
      |
      +---- stored policy revisions
      +---- accepted generation
      +---- observed target state
      |
      v
effective evidence-backed state
      |
      v
policy evaluator -> resolver eligibility input
```

Desired, accepted, observed and effective state remain distinct. Command text,
a graphical interface or an automation client is not canonical policy state.
All clients must use the same typed contracts and remain subject to local
authorization.

Operating mode is also separate from authority. `OBSERVE` and `RECOMMEND` are
non-mutating projections. `CONFIRM` and `AUTOMATIC_WITHIN_POLICY` still require
an exact authorized plan and domain-local acceptance; changing a client setting
cannot widen that authority.

## Integration boundaries

The policy evaluator determines whether a candidate may satisfy a request;
provider ranking chooses among eligible candidates. Management proposals cannot
bypass that order. Discovery, membership, dispatch authority and reputation do
not grant management authority. Federation does not transfer local policy
ownership: a domain discloses only the constraints needed for interoperable
selection and retains the right to refuse.

Product workflows, dashboards, IAM integrations and managed operations may
consume these contracts, but they cannot redefine them. Product repositories
and deployment topology are deliberately outside this public context map.
