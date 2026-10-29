# Analyst reporting

The Markdown renderer combines code-calculated priorities with
separately labeled AI commentary.

It verifies candidate and analysis fingerprints and requires exact
candidate coverage. Source and model text are escaped before insertion.

Each candidate includes:
- Asset owner and identity.
- Review score, band, and scoring reasons.
- Applicability, version-check, and patch-status uncertainty.
- Available EPSS score and date.
- Original KEV-required action.
- AI commentary and source labels.
- A deterministic analyst verification step.

The report includes coverage counts and source provenance.

Generated reports are ignored by Git.
docs/samples/analyst-report.md is a manually reviewed synthetic example.

Limitations:
- Escaping is defense in depth, not a general HTML sanitization library.
- Semantic accuracy still requires review.
- Freshness is displayed but not enforced.
- Report generation does not prove that an asset is affected.