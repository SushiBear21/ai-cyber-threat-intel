# Five-minute demonstration

## Preparation

- Confirm the latest GitHub Actions run is green.
- Open the README diagram.
- Open the reviewed synthetic report.
- Have a saved successful run and completion record available.
- Keep credentials and MFA setup off shared screens.

## 1. Explain the problem

"This pipeline turns public vulnerability intelligence into
source-backed review candidates for a fictional inventory."

Explain that it prioritizes analyst review, not confirmed compromise.

## 2. Show the evidence

Show KEV and EPSS source provenance, dates, and hashes.
Distinguish known exploitation from predicted exploitation probability.

## 3. Explain matching and scoring

Show one explicit synthetic rule and its candidate.
Explain needs_review, unknown versions, and unverified patch status.
Show each score contribution.

## 4. Show the report

Show deterministic priority information, the source-required action,
and separately labeled AI commentary.

Show the analyst review record.
Explain the observed model error that described an asset as KEV-listed
and how the reviewed sample corrected it.

## 5. Show automation

Show:
- A refreshed-source run.
- A completed-input skip.
- A scheduled invocation.
- Logs with stages and request IDs.
- Actual failure-test evidence and alert.

A skipped run is a valid demonstration of repeat-run handling.

## 6. Show testing

Open the passing GitHub Actions run.
Explain that local tests mock services.
Show the evaluation guide's limitations.

## Close

"This is a bounded sandbox implementation. Production work would need
stronger applicability evidence, broader semantic evaluation,
recovery exercises, lifecycle controls, and environment-specific design."

Do not describe future work as implemented.
If live processing fails, use saved evidence and explain the failure.