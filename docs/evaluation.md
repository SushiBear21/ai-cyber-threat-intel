# Evaluation

## Local suite

Run:

    .\.venv\Scripts\python.exe -m app.evaluate_local

The runner fails if tests fail or no tests are discovered.
It writes reports/local-test-results.json.

Current expected test count: 58.
Record the actual verified count after running.

Coverage includes:
- KEV validation.
- EPSS validation and explicit missing scores.
- Bounded HTTP retries and size limits.
- Normalization, duplicate rejection, and fingerprints.
- Synthetic applicability rules.
- Review-priority calculations.
- AI output structure and source-label checks.
- Report escaping and input consistency.
- Freshness limits and run identity.
- Run-claim handling.

## Live evidence

Record run IDs and outcomes for:
- Refreshed-source pipeline completion.
- Same-input repeat handling.
- Scheduled invocation.
- Invalid configuration causing a real Lambda failure.
- Restored valid configuration.
- Error metric, failure retention, and notification.
- Downloaded report hash verification.

## Observed model-output problems

1. Model returned JSON inside Markdown fences.
   Correction: accept a narrowly defined fence wrapper, then parse JSON.

2. Model omitted an exact uncertainty sentence.
   Correction: application code adds the fixed disclaimer.

3. Model discussed EPSS without including its source label.
   Correction: require all supplied evidence labels.

4. Model described an asset as KEV-listed.
   Status: semantic error requiring analyst correction.

5. Model used stronger risk/applicability language than warranted.
   Mitigation: targeted wording checks and manual review.
   These checks are incomplete.

## Limits

Passing structural tests does not prove semantic correctness.
A disclaimer does not neutralize contradictory commentary.
Source labels do not demonstrate sentence-level grounding.

No comprehensive model-quality grader, broad adversarial suite,
load test, or independent security assessment is implemented.

Mocked service tests and live demonstrations provide different evidence.
GitHub Actions runs local tests only.

Reports remain drafts until a human reviews them.