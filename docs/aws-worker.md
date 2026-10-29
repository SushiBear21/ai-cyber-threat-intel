# AWS intelligence reporting worker

## Verified deployment

- Function: ai-cti-worker
- Region: us-east-1
- Account: Portfolio-Sandbox, 359769212511
- Terraform-managed resources: 10
- Local tests: 49 passing
- Post-deployment Terraform plan: no changes
- Local Terraform state backup: hash verified

## Processing

The manually invoked worker reads inputs/prioritized.json from its
configured S3 bucket, generates Bedrock summaries, renders a Markdown
report, and saves artifacts under runs/<request-id>/.

Collection, normalization, asset assessment, and prioritization
currently run locally. Scheduling is not implemented yet.

Each completed run contains:
- analysis.json
- report.md
- complete.json

Consumers should use only runs containing complete.json.
Failed runs can leave partial artifacts.

A deployed run processed three candidates successfully.
The downloaded report matched the hash in its completion record.
AI commentary remains a draft requiring analyst review.

## Permissions and storage

The execution role can read the exact input key, write under runs/,
invoke Nova Lite, and write to its designated log group.

The bucket uses encryption, versioning, public-access blocking,
bucket-owner-enforced ownership, and an HTTPS-only policy.

No public function URL or scheduled trigger is configured.

## Troubleshooting observed

The first invocation failed with AccessDenied.
An administrator's HeadObject check showed the expected input was missing.
Uploading the input resolved the failure without expanding permissions.

## Operations and limitations

Logs record completion or failure metadata, not report content.
CloudWatch log retention is 14 days.
Alarms and scheduled execution remain future work.

Input limit: 5 MiB.
Analysis limit: 10 candidates.
Lambda timeout: 300 seconds.

No automatic feed refresh, freshness enforcement, run deduplication,
or Project 2 Bedrock Guardrail is implemented yet.

Terraform state remains local and is excluded from Git.
Keep protected backups under $HOME/TerraformBackups.

Successful execution and hash checks do not prove factual accuracy.
Review applicability wording and source attribution before accepting
or sharing an AI-generated report.

AWS resources incur charges. Review a destroy plan and preserve
state before cleanup. Versioned objects may prevent bucket deletion.