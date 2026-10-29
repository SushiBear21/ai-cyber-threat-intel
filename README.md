# AI Cyber Threat Intelligence Pipeline

A portfolio project that collects public vulnerability intelligence,
prioritizes findings against a fictional asset inventory, and produces
AI-assisted reports with source attribution.

## Planned capabilities

- Collect records from two public intelligence sources.
- Preserve source identifiers and collection timestamps.
- Validate, normalize, and deduplicate records.
- Match findings to a synthetic asset inventory.
- Calculate priority using explicit rules.
- Generate AI summaries grounded in collected evidence.
- Test data quality, report accuracy, and failure handling.
- Deploy scheduled processing and monitoring on AWS.

## Boundaries

This project uses public intelligence and fictional asset data.
It does not scan external systems or automatically remediate assets.
AI summaries support analyst review; they do not establish that an
organization is affected by a vulnerability.

## Status

Repository foundation. Collection and analysis are not implemented yet.