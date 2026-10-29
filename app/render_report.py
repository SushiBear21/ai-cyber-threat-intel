import argparse
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from app.prioritize import (
    PROJECT_ROOT,
    fingerprint,
    read_json,
    verify_priorities,
)


def safe(value):
    text = " ".join(str(value).split())
    text = html.escape(text, quote=True)

    # Prevent source/model text from creating Markdown formatting.
    for character in "\\`*_{}[]()#+!|>":
        text = text.replace(character, "\\" + character)

    return text


def render_report(priorities, analysis):
    candidates = verify_priorities(priorities)

    if analysis.get("synthetic") is not True:
        raise ValueError("Synthetic analysis required.")

    if (
        analysis.get("input_candidates_sha256")
        != priorities["candidates_sha256"]
    ):
        raise ValueError("Analysis references different candidates.")

    summaries = analysis["analyses"]
    if fingerprint(summaries) != analysis.get("analyses_sha256"):
        raise ValueError("Analysis fingerprint mismatch.")

    by_id = {item["candidate_id"]: item for item in summaries}
    expected_ids = {item["candidate_id"] for item in candidates}

    if len(by_id) != len(summaries) or set(by_id) != expected_ids:
        raise ValueError("Analysis coverage does not match candidates.")

    lines = [
        "# Synthetic threat intelligence review",
        "",
        "AI-assisted draft — analyst review required.",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Scoring policy: {safe(priorities['policy']['version'])}",
        f"Model: {safe(analysis['model_id'])}",
        "",
        "## Scope",
        "",
        "This is a KEV-led snapshot with partial EPSS enrichment.",
        "Candidate matching uses explicit synthetic review rules.",
        "No asset is confirmed vulnerable or compromised.",
        "",
        "Coverage:",
    ]

    for name, count in priorities["coverage"].items():
        lines.append(f"- {safe(name)}: {count}")

    lines += [
        "",
        "## Candidate reviews",
        "",
    ]

    for candidate in candidates:
        assessment = candidate["assessment"]
        finding = candidate["finding"]
        commentary = by_id[candidate["candidate_id"]]

        lines += [
            f"### {safe(finding['cve_id'])} / {safe(assessment['asset_id'])}",
            "",
            f"- Asset: {safe(assessment['asset_name'])}",
            f"- Owner: {safe(assessment['owner'])}",
            f"- Review score: {candidate['review_score']}/100",
            f"- Review band: {safe(candidate['review_band'])}",
            "- Applicability: needs_review",
            f"- Inventory version: {safe(assessment['inventory_version'])}",
            "- Affected-version check: not performed",
            "- Patch status: not assessed",
            "",
            "**Scoring reasons**",
            "",
        ]

        for reason in candidate["reasons"]:
            lines.append(
                f"- {safe(reason['signal'])}: +{reason['points']}"
            )

        if candidate["data_gaps"]:
            lines += ["", "**Data gaps**", ""]
            lines += [
                f"- {safe(gap)}" for gap in candidate["data_gaps"]
            ]

        epss = finding["epss"]
        if epss["status"] == "available":
            lines += [
                "",
                (
                    f"EPSS probability: {epss['probability']:.4%}; "
                    f"percentile: {epss['percentile']:.4%}; "
                    f"score date: {safe(epss['score_date'])}."
                ),
            ]

        lines += [
            "",
            "**Source-required action — KEV**",
            "",
            safe(finding["required_action"]),
            "",
            "**AI commentary — unverified draft**",
            "",
            safe(commentary["summary"]),
            "",
            "Source labels: " + ", ".join(
                safe(label) for label in commentary["citations"]
            ),
            "",
            "**Analyst next step**",
            "",
            "Verify the installed component, affected version, configuration, "
            "and patch status before deciding remediation.",
            "",
        ]

    lines += ["## Source provenance", ""]

    for label, source in priorities["sources"].items():
        lines += [
            f"### {safe(label.upper())}",
            "",
            f"- URL: {safe(source['requested_url'])}",
            f"- Collected: {safe(source['collected_at'])}",
            f"- Raw SHA-256: {safe(source['raw_sha256'])}",
            "",
        ]

    lines += [
        "ASSET refers to the synthetic inventory and review rules.",
        f"Inventory evidence is retained in the candidate assessments.",
        "",
        "## Limitations",
        "",
        "Scores are exercise rules, not an industry standard.",
        "Missing enrichment does not mean zero risk.",
        "Unmatched assets and findings have not been ruled out.",
        "AI source labels do not prove every claim.",
        "This report uses explicit snapshots and does not enforce freshness.",
        "",
    ]

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--priorities", required=True)
    parser.add_argument("--analysis", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        text = render_report(
            read_json(args.priorities),
            read_json(args.analysis),
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        print(f"PASS: report written to {output}")

    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Report failed: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())