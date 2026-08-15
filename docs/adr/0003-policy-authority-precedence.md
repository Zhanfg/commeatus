# ADR-0003: Policy Authority Precedence

Status: Accepted

## Decision

Policy authority is ordered from strongest to weakest:

```text
UserHard
> Safety
> Compatibility
> Adaptive
> Default
```

Rules are evaluated by authority tier before rule order. Inside one tier, deterministic first-match semantics apply.

## Rationale

Adaptive behavior is useful only while it remains subordinate to explicit user intent and safety constraints. Compatibility layers may preserve imported semantics, but they must not gain authority over native user hard rules or safety policy.

This ordering is part of the native runtime contract, not a UI convention.

## Consequences

- a user-forced `DIRECT`, route, or reject decision cannot be silently changed by adaptive learning;
- safety policy can contain failures without giving Smart/Adaptive control over the whole network;
- compatibility imports remain constrained to their authority tier;
- later policy compilers may optimize indexes, but they must preserve the same observable precedence.
