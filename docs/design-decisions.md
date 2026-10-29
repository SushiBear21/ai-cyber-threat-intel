# Design decisions

## KEV-led scope

The normalized dataset starts from KEV.
This focuses the exercise on known-exploited vulnerabilities.
It does not cover all vulnerabilities affecting an organization.

## Bounded EPSS lookups

The API enriches CVEs in the small exercise-rule set.
This avoids treating a lookup API as a bulk synchronization mechanism.
A larger workload should use the appropriate daily dataset.

## Explicit synthetic applicability rules

Rules are auditable and testable.
They demonstrate workflow integration without claiming comprehensive
product or version matching.

## Code-calculated priorities

Weights and reasons remain inspectable.
AI cannot change the authoritative review score.
The weights are exercise policy and need real stakeholder validation.

## AI commentary with human review

The model summarizes evidence but can misattribute claims.
Strict output structure and source labels improve handling without
proving grounding.

The observed KEV asset-attribution error remains documented.
Reviewed samples are separate from original generated artifacts.

## Single Lambda pipeline

A single function reduces infrastructure complexity for three candidates.
Stages share one timeout, and a failure can require repeating work.
A larger workload may justify separate stages and orchestration.

## Conditional run tracking

DynamoDB claims prevent concurrent ownership and skip completed inputs.
Leases support recovery from unfinished execution.
Crashes near completion can still cause repeated model calls.
This is not exactly-once processing.

## Retained artifacts

Source responses and intermediate evidence support investigation.
They create storage and retention responsibilities.
No automated evidence lifecycle is implemented yet.

## Separate delivery and execution failure handling

A Scheduler delivery success does not establish Lambda processing success.
The failure queue and Lambda error metrics cover different paths.

## Local Terraform state

The project currently relies on protected local state backups.
Remote state is a future operational improvement.
Project 1's backend is not automatically reused.

## Production gaps

- Authoritative applicability and patch evidence.
- Broader model and adversarial evaluation.
- Recovery and load exercises.
- Heartbeat monitoring.
- Retention and access lifecycle controls.
- Environment-specific deployment and network review.