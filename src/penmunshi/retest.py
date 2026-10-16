"""Deterministic retest mode. Compares two engagement reports and categorizes findings."""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .models import Report, VerifiedFinding

RetestStatus = Literal["resolved", "open", "regressed", "new"]

_SEVERITY_RANKS: dict[str, int] = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "None": 1,
    "Unrated": 0,
}


def _norm(s: str) -> str:
    """Normalize text for fuzzy matching."""
    s = s.lower().strip()
    s = re.sub(r"[^\w\s]", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def _similarity(s1: str, s2: str) -> float:
    if not s1 or not s2:
        return 0.0
    return difflib.SequenceMatcher(None, _norm(s1), _norm(s2)).ratio()


def finding_similarity(f1: VerifiedFinding, f2: VerifiedFinding) -> float:
    """Compute similarity between two findings based on title, asset, and CWE."""
    # Exact title match
    if _norm(f1.title) == _norm(f2.title):
        return 1.0

    title_sim = _similarity(f1.title, f2.title)

    # Asset similarity
    asset_sim = _similarity(f1.affected_asset, f2.affected_asset) if f1.affected_asset and f2.affected_asset else 0.0

    # CWE overlap
    f1_cwes = {c.id for c in f1.cwe}
    f2_cwes = {c.id for c in f2.cwe}
    cwe_sim = 1.0 if (f1_cwes and f2_cwes and f1_cwes.intersection(f2_cwes)) else 0.0

    if f1.affected_asset and f2.affected_asset:
        score = 0.5 * title_sim + 0.35 * asset_sim + 0.15 * cwe_sim
    else:
        score = 0.8 * title_sim + 0.2 * cwe_sim

    # Same finding ID gives a slight boost
    if f1.id == f2.id:
        score = min(1.0, score + 0.15)

    return score


@dataclass
class RetestItem:
    status: RetestStatus
    title: str
    asset: str
    old_id: str | None = None
    new_id: str | None = None
    old_severity: str | None = None
    new_severity: str | None = None
    old_cvss: float | None = None
    new_cvss: float | None = None
    notes: str = ""


@dataclass
class RetestResult:
    old_project: str
    new_project: str
    items: list[RetestItem] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {"resolved": 0, "open": 0, "regressed": 0, "new": 0}
        for item in self.items:
            c[item.status] = c.get(item.status, 0) + 1
        return c

    @property
    def resolved(self) -> list[RetestItem]:
        return [i for i in self.items if i.status == "resolved"]

    @property
    def open(self) -> list[RetestItem]:
        return [i for i in self.items if i.status == "open"]

    @property
    def regressed(self) -> list[RetestItem]:
        return [i for i in self.items if i.status == "regressed"]

    @property
    def new(self) -> list[RetestItem]:
        return [i for i in self.items if i.status == "new"]

    def render_markdown(self) -> str:
        lines = [
            f"# Retest Comparison: {self.old_project} -> {self.new_project}",
            "",
            f"**Summary**: {self.counts['resolved']} resolved, {self.counts['open']} open, "
            f"{self.counts['regressed']} regressed, {self.counts['new']} new.",
            "",
            "| Status | Old ID | New ID | Severity Change | CVSS Change | Finding Title & Asset | Notes |",
            "|:-------|:-------|:-------|:----------------|:------------|:----------------------|:------|",
        ]
        status_labels = {
            "resolved": "RESOLVED",
            "open": "OPEN",
            "regressed": "REGRESSED",
            "new": "NEW",
        }
        for item in self.items:
            sev_change = f"{item.old_severity or '-'} -> {item.new_severity or '-'}"
            cvss_change = (
                f"{item.old_cvss if item.old_cvss is not None else '-'} -> "
                f"{item.new_cvss if item.new_cvss is not None else '-'}"
            )
            title_asset = f"**{item.title}** (`{item.asset}`)" if item.asset else f"**{item.title}**"
            lines.append(
                f"| **{status_labels[item.status]}** | {item.old_id or '-'} | {item.new_id or '-'} | "
                f"{sev_change} | {cvss_change} | {title_asset} | {item.notes or '-'} |"
            )
        return "\n".join(lines)

    def render_table(self) -> str:
        header = f"=== PenMunshi Retest: {self.old_project} vs {self.new_project} ==="
        sep = "-" * 88
        rows = [
            header,
            sep,
            f"{'STATUS':<11} {'OLD ID':<8} {'NEW ID':<8} {'SEVERITY':<20} {'TITLE & ASSET':<40}",
            sep,
        ]
        for it in self.items:
            st = it.status.upper()
            o_id = it.old_id or "-"
            n_id = it.new_id or "-"
            sev = f"{it.old_severity or '-'} -> {it.new_severity or '-'}"
            t_a = f"{it.title} ({it.asset})" if it.asset else it.title
            if len(t_a) > 38:
                t_a = t_a[:35] + "..."
            rows.append(f"{st:<11} {o_id:<8} {n_id:<8} {sev:<20} {t_a:<40}")
        rows.append(sep)
        rows.append(
            f"Summary: {self.counts['resolved']} resolved, {self.counts['open']} open, "
            f"{self.counts['regressed']} regressed, {self.counts['new']} new."
        )
        return "\n".join(rows)


def compare_reports(
    old_report: Report,
    new_report: Report,
    match_threshold: float = 0.55,
) -> RetestResult:
    """Compare an old report and a new report, deterministically categorizing findings."""
    old_findings = list(old_report.findings)
    new_findings = list(new_report.findings)

    # Compute pairwise similarities
    pairs: list[tuple[float, VerifiedFinding, VerifiedFinding]] = []
    for f_old in old_findings:
        for f_new in new_findings:
            sim = finding_similarity(f_old, f_new)
            if sim >= match_threshold:
                pairs.append((sim, f_old, f_new))

    # Sort descending by similarity score for greedy optimal matching
    pairs.sort(key=lambda x: x[0], reverse=True)

    matched_old: dict[str, VerifiedFinding] = {}
    matched_new: dict[str, VerifiedFinding] = {}
    matches: list[tuple[VerifiedFinding, VerifiedFinding]] = []

    for _sim, f_old, f_new in pairs:
        if f_old.id not in matched_old and f_new.id not in matched_new:
            matched_old[f_old.id] = f_old
            matched_new[f_new.id] = f_new
            matches.append((f_old, f_new))

    items: list[RetestItem] = []

    # 1. Evaluate matched findings: open vs regressed
    for f_old, f_new in matches:
        old_rank = _SEVERITY_RANKS.get(f_old.severity, 0)
        new_rank = _SEVERITY_RANKS.get(f_new.severity, 0)
        cvss_diff = (f_new.cvss_score or 0.0) - (f_old.cvss_score or 0.0)

        is_regressed = new_rank > old_rank or cvss_diff >= 0.15

        if is_regressed:
            status = "regressed"
            notes = f"Severity escalated ({f_old.severity} -> {f_new.severity})"
        elif new_rank < old_rank:
            status = "open"
            notes = f"Partially mitigated ({f_old.severity} -> {f_new.severity})"
        else:
            status = "open"
            notes = "Unchanged"

        items.append(
            RetestItem(
                status=status,
                title=f_new.title,
                asset=f_new.affected_asset or f_old.affected_asset,
                old_id=f_old.id,
                new_id=f_new.id,
                old_severity=f_old.severity,
                new_severity=f_new.severity,
                old_cvss=f_old.cvss_score,
                new_cvss=f_new.cvss_score,
                notes=notes,
            )
        )

    # 2. Old findings without match -> resolved
    for f_old in old_findings:
        if f_old.id not in matched_old:
            items.append(
                RetestItem(
                    status="resolved",
                    title=f_old.title,
                    asset=f_old.affected_asset,
                    old_id=f_old.id,
                    new_id=None,
                    old_severity=f_old.severity,
                    new_severity=None,
                    old_cvss=f_old.cvss_score,
                    new_cvss=None,
                    notes="Finding verified remediated and closed",
                )
            )

    # 3. New findings without match -> new
    for f_new in new_findings:
        if f_new.id not in matched_new:
            items.append(
                RetestItem(
                    status="new",
                    title=f_new.title,
                    asset=f_new.affected_asset,
                    old_id=None,
                    new_id=f_new.id,
                    old_severity=None,
                    new_severity=f_new.severity,
                    old_cvss=None,
                    new_cvss=f_new.cvss_score,
                    notes="New finding discovered in retest",
                )
            )

    # Sort order: regressed, open, new, resolved
    status_priority = {"regressed": 0, "open": 1, "new": 2, "resolved": 3}
    items.sort(key=lambda it: status_priority[it.status])

    return RetestResult(
        old_project=old_report.engagement.project,
        new_project=new_report.engagement.project,
        items=items,
    )


def retest_files(old_path: Path | str, new_path: Path | str) -> RetestResult:
    """Load two report JSON files and generate retest comparison."""
    old_data = json.loads(Path(old_path).read_text(encoding="utf-8"))
    new_data = json.loads(Path(new_path).read_text(encoding="utf-8"))
    old_report = Report.model_validate(old_data)
    new_report = Report.model_validate(new_data)
    return compare_reports(old_report, new_report)
