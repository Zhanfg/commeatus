# ADR-0002: Actions Are Not Endpoints

Status: Accepted

## Context

Proxy ecosystems often accumulate compatibility debt when routing actions are represented as special outbounds or endpoints. That makes concepts such as reject, DNS hijack, sniffing, rewriting, and marking share a lifecycle with actual egress transports.

## Decision

Commeatus models an action and an endpoint as different native concepts.

An endpoint answers:

> Where and how can a routed flow leave the core?

An action answers:

> What should happen to this flow?

For the V0.1 slice:

- `Endpoint::Direct` is an endpoint.
- `ExecutionAction::Route { endpoint }` is an action that selects an endpoint.
- `ExecutionAction::Reject { reason }` is an action with no endpoint.

Compatibility importers may translate legacy "block outbound" or equivalent syntax into a native reject action, but the legacy object must terminate at the compatibility boundary.

## Consequences

- endpoint health state cannot accidentally be attached to reject/DNS/sniff actions;
- future endpoint capability discovery remains about actual egress targets;
- policy and execution remain independently evolvable;
- compatibility syntax cannot redefine the native runtime ontology.
