from __future__ import annotations

from ..models import Report
from .common import count_severities, label, sort_findings


def _list(items: list[str], ordered: bool = False) -> str:
    if not items:
        return "_None provided._\n"
    return "\n".join(f"{i}. {x}" if ordered else f"- {x}" for i, x in enumerate(items, 1)) + "\n"


def render_markdown(report: Report) -> str:
    e = report.engagement
    findings = sort_findings(report.findings)
    counts = report.severity_counts or count_severities(findings)
    out = [f"# Penetration Test Report: {e.project}", ""]
    out += [
        f"- **Client:** {e.client}",
        f"- **Tester:** {e.tester or '-'}",
        f"- **Dates:** {e.date_range or '-'}",
        f"- **Methodology:** {e.methodology}",
        f"- **Scope:** {', '.join(e.scope) if e.scope else '-'}",
        f"- **Reviewed by:** {e.reviewed_by or '(pending human review)'}",
        "",
        "> AI-assisted draft. Scores, identifiers, quotes and secret masking were checked by "
        "software; a human tester must review every finding before delivery.",
        "",
        "## Executive summary",
        "",
        report.executive_summary or "_No summary generated._",
        "",
        "| Severity | Findings |",
        "|---|---|",
    ]
    out += [f"| {label(k)} | {v} |" for k, v in counts.items()]
    out += ["", "## Findings overview", "", "| ID | Title | Severity | CVSS |", "|---|---|---|---|"]
    out += [
        f"| {f.id} | {f.title} | {label(f.severity)} | {f.cvss_score if f.cvss_score is not None else '-'} |"
        for f in findings
    ]
    for f in findings:
        out += ["", f"## {f.id}: {f.title}", ""]
        out += [
            f"- **Severity:** {label(f.severity)} ({f.cvss_score if f.cvss_score is not None else 'n/a'})",
            f"- **CVSS vector:** `{f.cvss_vector or 'n/a'}` (computed by software)",
            f"- **Affected asset:** {f.affected_asset or '-'}",
            "- **Weakness:** " + (", ".join(f"{c.id} {c.name}" for c in f.cwe) or "-"),
            "- **CVE:** " + (", ".join(c.id + (" (known exploited)" if c.known_exploited else "") for c in f.cve) or "-"),
            f"- **Confidence:** {f.confidence} | **Status:** {f.status}",
            "",
            "### Summary",
            "",
            f.summary,
            "",
            "### Description",
            "",
            f.description,
            "",
            "### Steps to reproduce",
            "",
            _list(f.steps_to_reproduce, ordered=True),
            "### Impact",
            "",
            f.impact,
            "",
            "### Remediation",
            "",
            _list(f.remediation),
        ]
        shown = [ev for ev in f.evidence if ev.transcript.strip()]
        if shown:
            out += ["### Evidence", ""]
            for ev in shown:
                out += [f"**{ev.name}**", "", "```text", ev.transcript.strip(), "```", ""]
    out += ["", "## Appendix: verification log", ""]
    for f in findings:
        out.append(f"### {f.id}")
        if f.removed_ids:
            out += [f"- Removed {r.kind.upper()} `{r.id}`: {r.reason}" for r in f.removed_ids]
        bad = [c for c in f.claims if not c.supported]
        out += [f"- Unsupported claim: {c.text} (quote not found)" for c in bad]
        out += [f"- Masked {s.kind} `{s.preview}` in {s.source}" for s in f.secrets]
        out += [f"- {i.level.upper()} {i.code}: {i.message}" for i in f.lint]
        out.append(f"- Claims verified: {sum(c.supported for c in f.claims)} of {len(f.claims)}")
        out.append("")
    t = report.tool
    out.append(f"_Generated locally by PenMunshi {t.get('version', '')} with model {t.get('model', '')} on {report.generated_at}._")
    return "\n".join(out) + "\n"
