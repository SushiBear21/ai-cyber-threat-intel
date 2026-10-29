# Review prioritization

Policy version: exercise-1.

This score ranks candidate-review urgency. It is not an industry
risk score, an exploitation probability, or confirmation of vulnerability.

Points:
- KEV-listed: 50.
- Internet-exposed: 25.
- High criticality: 15; medium: 10; low: 0.
- Available EPSS probability at least 0.50: 10.

Bands:
- 85–100: expedited_review.
- 65–84: elevated_review.
- Below 65: standard_review.

Weights and thresholds are exercise decisions, not publisher guidance.

Missing EPSS contributes no EPSS points and is explicitly listed as a gap.
A low or missing EPSS score does not remove KEV points.
Applicability remains needs_review.

Inputs must refer to the same normalized findings snapshot.
Output preserves source evidence, assessment information, scoring reasons,
coverage counts, policy version, and fingerprints.

Coverage remains limited to the supplied synthetic rules.
Scores do not account for all real-world factors, such as compensating
controls, confirmed patch status, or actual business impact.

Candidate fingerprints detect content changes, not publisher authenticity.