# ADR-XXXX: <Short decision title>

- **Status**: Proposed | Accepted | Deprecated | Superseded by ADR-YYYY
- **Date**: YYYY-MM-DD
- **Deciders**: <names or roles>
- **Related**: <issue / PR / ADR links>

## Context

What is the problem? What forces are in play (technical, organizational,
timeline, cost)? Why are we choosing *now* to decide this? Keep it to a
few paragraphs.

## Decision

What we decided, stated in the active voice. One to three sentences. Keep
rationale and alternatives in their own sections.

## Consequences

Positive, negative, and neutral consequences. Be honest about what this
locks us into and what it costs.

- **Positive**: …
- **Negative**: …
- **Neutral**: …

## Alternatives considered

Brief write-up of each serious alternative and why it was rejected. One
paragraph each. Do not skip this section — future readers want to know
what was weighed.

## Future work

**If this ADR introduces new hyperparameters, training configuration, or
model artifacts**, flag that we will eventually want to migrate hyperparameter
tracking and the artifact registry from the in-repo `models/` directory and
`docs/MODEL_JOURNAL.md` to a proper experiment tracker — candidates: MLflow,
Weights & Biases, or SAP AI Launchpad. The journal approach works at
hackathon scale; it does not scale past a handful of concurrent experiments
or more than one AI/ML contributor. Flag the migration threshold in this
section so we remember to trigger it.

Other follow-ups, open questions, deferred work.

## References

Links to source material, benchmarks, vendor docs, relevant incidents.
