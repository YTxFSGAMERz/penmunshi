from __future__ import annotations

from jinja2 import Environment, PackageLoader

from ..models import Report
from .common import count_severities, label, sort_findings

_CLASS = {
    "Critical": "crit",
    "High": "high",
    "Medium": "med",
    "Low": "low",
    "None": "info",
    "Unrated": "unrated",
}


def render_html(report: Report) -> str:
    env = Environment(loader=PackageLoader("penmunshi", "report/templates"), autoescape=True)
    template = env.get_template("report.html.j2")
    findings = sort_findings(report.findings)
    return template.render(
        report=report,
        e=report.engagement,
        findings=findings,
        counts=report.severity_counts or count_severities(findings),
        label=label,
        sev_class=lambda s: _CLASS.get(s, "unrated"),
    )
