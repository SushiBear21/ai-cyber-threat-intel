# Operations

## Environment

Account: Portfolio-Sandbox, 359769212511.
Region: us-east-1.
Function: ai-cti-worker.
Log group: /aws/lambda/ai-cti-worker.
Run table: ai-cti-runs.

## Configuration

Trusted administrators maintain:
- inputs/assets.json
- inputs/review-rules.json

Validate local configuration and upload it with S3-managed encryption.
Do not store real organizational data in this exercise.

The earlier inputs/prioritized.json belongs to the Session 9 worker.
The scheduled worker constructs fresh priorities itself.

## Manual execution

    aws lambda invoke --function-name ai-cti-worker --cli-read-timeout 660 --region us-east-1 --profile portfolio-sandbox --no-cli-pager reports/worker-response.json

Inspect both invocation metadata and the response file.
StatusCode 200 alone does not prove function success.

## Scheduling

The Terraform default is disabled.
A local ignored schedule.auto.tfvars controls activation.

To pause:
- Set schedule_enabled = false in that file.
- Run terraform plan and review the schedule change.
- Apply the saved plan.

Disabling the schedule prevents future scheduled delivery; it does not
cancel work already queued or running.

## Completion and repeat runs

A successful run returns report and completion keys.
Verify downloaded report bytes against the completion SHA-256.

DynamoDB tracks run identity and the successful report pointer.
A completed input returns skipped.

An in-progress run has a 15-minute lease.
Investigate before changing or deleting run records.
Do not delete records merely to force another model generation.

## Failure investigation

Read recent logs:

    aws logs tail /aws/lambda/ai-cti-worker --since 30m --region us-east-1 --profile portfolio-sandbox

Inspect the stage and error class:
- configuration: object existence, input schema, role permissions.
- collection: network, source status, response validation, freshness.
- processing: source joins, inventory rules, candidate bounds.
- claim: run tracking or equivalent work already active.
- archive: S3 write permissions or service errors.
- analysis: model access, output format, citation validation.
- report: fingerprint and coverage checks.
- record_completion: DynamoDB ownership and status.

A timeout can leave a claim until its lease expires.

## Failure queue

The queue retains Scheduler delivery failures and failed asynchronous
Lambda invocation records for up to 14 days.

Receiving a message does not remediate it.
Inspect it, correlate the request, resolve the cause, and decide whether
reprocessing is appropriate before deleting the message.

The configuration-test message is expected evidence, not a live attack.

## Logging and alerts

Logs retain 14 days.
Alarms cover Lambda errors, long duration, and visible failure messages.

No absent-run heartbeat is configured.
Check that the schedule is enabled when daily processing is expected.

## State and deployment

Terraform state remains local and ignored by Git.
Keep hash-verified backups under $HOME/TerraformBackups.

Rebuild the package after runtime code or dependency changes.
Run tests, review Terraform plan, apply, then verify a live run.

## Costs

Review billing and budget alerts periodically.
Costs include Bedrock, Lambda, S3, DynamoDB including point-in-time
recovery, CloudWatch, Scheduler, SNS, and SQS.

DynamoDB run records and versioned S3 objects accumulate.
No automatic retention lifecycle is implemented for report evidence.

## Cleanup

1. Disable the schedule.
2. Preserve required state and evidence.
3. Review terraform plan -destroy.
4. Account for versioned objects and retained messages.
5. Apply teardown only after reviewing the intended resources.

Do not run cleanup from Project 1's Terraform folder.