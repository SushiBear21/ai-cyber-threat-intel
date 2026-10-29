# Synthetic asset applicability assessment

## Inputs

- Normalized KEV-led findings from Session 4.
- data/synthetic/assets.json.
- data/synthetic/review-rules.json.

All organizational assets and review rules are synthetic.

## Method

Join finding CVE identifiers to explicit review rules.
Join each rule's component_key to inventory components.

Product-name similarity alone does not create a match.

Each candidate includes:
- Asset and component identifiers.
- Owner, criticality, and internet exposure.
- Review-rule identifier and basis.
- Inventory version.
- Explicit applicability and verification status.

## Interpretation

All candidates are marked needs_review.
Version checks are not performed.
Patch status is not assessed.

An explicit rule match does not establish that an asset is vulnerable
or compromised. Confirm installed components, affected versions,
configuration, and patch status using authoritative evidence.

Findings and assets without rule matches are listed.
No match means coverage is incomplete, not that the asset is safe.

The three supplied rules demonstrate the workflow; they are not
a comprehensive vulnerability applicability database.

## Provenance

The assessment records:
- Input normalized findings fingerprint.
- Inventory fingerprint.
- Review-rule fingerprint.
- Source provenance carried from the normalized dataset.

The normalized findings fingerprint is checked before processing.

## Validation

Inventory validation requires:
- Explicit synthetic designation.
- Unique asset and component identifiers.
- Owner and component information.
- Low, medium, or high business criticality.
- Explicit boolean internet exposure.

Rules require unique identifiers and CVE/component pairs.
Duplicate normalized finding CVEs are rejected.

## Run

From the repository root:

    .\.venv\Scripts\python.exe -m app.assess_assets --findings PATH_TO_FINDINGS_JSON --inventory .\data\synthetic\assets.json --rules .\data\synthetic\review-rules.json

Output is written under data/processed/ and excluded from Git.

## Expected exercise outcome

Using the supplied inventory and Session 4 snapshots:
- Three candidate asset assessments.
- One asset without a review-rule match.
- All candidates require analyst review.

## Limitations

No scanning, installed-version discovery, advisory parsing,
CPE matching, version-range evaluation, or patch verification.

Inventory exposure and criticality are supplied exercise inputs.
Real use would require ownership and freshness controls.

Prioritization comes in Session 6 and must preserve these
applicability uncertainties.