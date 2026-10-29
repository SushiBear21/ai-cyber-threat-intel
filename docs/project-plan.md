# Project plan: AI Cyber Threat Intelligence Pipeline

## Goal

Turn public vulnerability intelligence into a prioritized,
source-backed report for a fictional organization.

## Initial scope

- Two public intelligence sources.
- A small synthetic asset inventory.
- Explicit, testable prioritization rules.
- AI-assisted summaries grounded in collected evidence.
- One Markdown analyst report format.
- Scheduled AWS processing with monitoring.

Source selection and endpoint verification occur in Sessions 2 and 3.

## Processing stages

Collect → validate → normalize → enrich → match assets →
prioritize → summarize → report.

Preserve original source records and collection timestamps.
Treat feed content as untrusted input.

## Design rules

- Prioritization is calculated by code, with reasons shown.
- AI explains findings; it does not assign the authoritative score.
- Product-name similarity alone does not confirm vulnerability.
- Uncertain applicability is explicitly labeled for analyst review.
- Missing data is distinguished from a negative finding.
- Reports identify sources and their freshness.
- No external scanning or automatic remediation.
- Use public intelligence and fictional organizational data only.

## Sessions

1. Foundation and scope.
2. First intelligence source.
3. Second intelligence source.
4. Normalization and deduplication.
5. Synthetic asset inventory and applicability matching.
6. Explainable prioritization.
7. AI-assisted analysis.
8. Report generation.
9. AWS deployment.
10. Scheduling and monitoring.
11. Automated evaluation and GitHub Actions.
12. Portfolio documentation and demo.

## Initial architecture

Local Python processing first.
After validation, deploy processing and storage to AWS.

Planned AWS components:
- S3 for collected data and reports.
- Lambda for processing, if runtime and dependency sizes fit.
- Bedrock for AI summaries.
- EventBridge Scheduler for scheduled execution.
- CloudWatch and SNS for operational monitoring.
- Terraform for infrastructure.

Deployment choices will be revisited after measuring the local workload.

## Completion criteria

- Both sources can be collected with validation and failure handling.
- Findings retain source provenance.
- Asset matches and priorities have inspectable reasons.
- AI summaries include references and preserve uncertainty.
- Repeated runs handle duplicates and updates predictably.
- Automated tests cover important processing and security boundaries.
- A scheduled AWS run and failure notification are demonstrated.
- Documentation explains setup, costs, cleanup, and limitations.

Project 2.5 adds an agentic workflow after this pipeline is complete.