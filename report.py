"""
Report generator — outputs a clean Markdown report from a PipelineRun.
"""

import os
from dataclasses import asdict


def generate_report(run, executive_summary: str):
    os.makedirs("reports", exist_ok=True)
    slug = run.target.replace("https://", "").replace("http://", "").replace("/", "_").rstrip("_")
    path = f"reports/{slug}.md"

    sev_order   = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_emoji   = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
    sev_counts  = {s: 0 for s in sev_order}
    for f in run.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    lines = []

    # ── Header ───────────────────────────────
    lines += [
        f"# Security Assessment Report",
        f"",
        f"**Target:** `{run.target}`  ",
        f"**Scan started:** {run.started_at}  ",
        f"**Total findings:** {len(run.findings)}  ",
        f"**Auto-flagged (HIGH+):** {len(run.flagged)}",
        f"",
    ]

    # ── Executive Summary ─────────────────────
    lines += [
        "## Executive Summary",
        "",
        executive_summary,
        "",
    ]

    # ── Risk Overview ─────────────────────────
    lines += ["## Risk Overview", "", "| Severity | Count |", "|----------|-------|"]
    for sev in sev_order:
        count = sev_counts[sev]
        if count:
            lines.append(f"| {sev_emoji[sev]} {sev} | {count} |")
    lines.append("")

    # ── Auto-Flagged ──────────────────────────
    if run.flagged:
        lines += ["## Auto-Flagged (Sent to Repeater)", ""]
        for f in run.flagged:
            lines += [
                f"### {sev_emoji[f.severity]} {f.category}",
                f"- **Endpoint:** `{f.method} {f.endpoint}`",
                f"- **Severity:** {f.severity}",
                f"- **Request ID:** `{f.request_id}`",
                f"- **Description:** {f.description}",
                f"- **Evidence:** `{f.evidence}`",
                f"- **Fix:** {f.recommendation}",
                "",
            ]

    # ── All Findings ──────────────────────────
    lines += ["## All Findings", ""]
    grouped = {s: [] for s in sev_order}
    for f in run.findings:
        grouped[f.severity].append(f)

    for sev in sev_order:
        findings = grouped[sev]
        if not findings:
            continue
        lines += [f"### {sev_emoji[sev]} {sev}", ""]
        for i, f in enumerate(findings, 1):
            lines += [
                f"#### {i}. {f.category} — `{f.endpoint}`",
                f"",
                f"| Field | Detail |",
                f"|-------|--------|",
                f"| Method | `{f.method}` |",
                f"| Category | {f.category} |",
                f"| Timestamp | {f.timestamp} |",
                f"",
                f"**Description:** {f.description}",
                f"",
                f"**Evidence:**",
                f"```",
                f.evidence,
                f"```",
                f"",
                f"**Recommendation:** {f.recommendation}",
                f"",
            ]

    # ── Errors ────────────────────────────────
    if run.errors:
        lines += ["## Pipeline Errors", ""]
        for e in run.errors:
            lines.append(f"- {e}")
        lines.append("")

    with open(path, "w") as fh:
        fh.write("\n".join(lines))

    print(f"[Report] Written to {path}")
    return path
