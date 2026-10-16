"""Data models. `FindingDraft` is what the LLM may return; `VerifiedFinding` is what the
pipeline outputs after deterministic verification. Severity is never taken from the model."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["Critical", "High", "Medium", "Low", "None", "Unrated"]
Confidence = Literal["confirmed", "likely", "needs_more_evidence"]
Status = Literal["ready", "needs_review"]


# ---------------------------------------------------------------- what the model drafts
class CvssMetrics(BaseModel):
    AV: Literal["N", "A", "L", "P"]
    AC: Literal["L", "H"]
    PR: Literal["N", "L", "H"]
    UI: Literal["N", "R"]
    S: Literal["U", "C"]
    C: Literal["N", "L", "H"]
    I: Literal["N", "L", "H"]  # noqa: E741 - CVSS metric name
    A: Literal["N", "L", "H"]


class ClaimDraft(BaseModel):
    text: str
    evidence_ref: str = "notes"
    quote: str


class FindingDraft(BaseModel):
    title: str
    affected_asset: str = ""
    summary: str
    description: str
    steps_to_reproduce: list[str] = Field(default_factory=list)
    impact: str
    remediation: list[str] = Field(default_factory=list)
    cvss: CvssMetrics
    cvss_rationale: str = ""
    cwe_ids: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    claims: list[ClaimDraft] = Field(default_factory=list)
    confidence: Confidence = "needs_more_evidence"

    @classmethod
    def from_llm(cls, data: dict) -> FindingDraft:
        """Tolerant parse for small models: stringify ids, wrap scalars in lists.

        Unknown keys (for example a rogue "severity") are ignored on purpose:
        severity belongs to code, not to the model.
        """
        d = dict(data)
        for key in ("cwe_ids", "cve_ids", "steps_to_reproduce", "remediation"):
            v = d.get(key, [])
            if v is None:
                v = []
            if not isinstance(v, list):
                v = [v]
            d[key] = [str(x) for x in v if x is not None]
        return cls.model_validate(d)


# ---------------------------------------------------------------- what the pipeline outputs
class CweRef(BaseModel):
    id: str
    name: str
    verified: bool


class CveRef(BaseModel):
    id: str
    known_exploited: bool = False


class RemovedId(BaseModel):
    id: str
    kind: Literal["cve", "cwe"]
    reason: str


class ClaimResult(BaseModel):
    text: str
    evidence_ref: str
    quote: str
    supported: bool
    score: float
    found_in: str = ""
    quote_start: int | None = None
    quote_end: int | None = None


class SecretPublic(BaseModel):
    """A masked description of a detected secret. The raw value is never stored."""

    kind: str
    preview: str
    confidence: str
    checksum_ok: bool | None = None
    source: str = ""


class EvidenceItem(BaseModel):
    name: str
    kind: Literal["screenshot", "text"] = "text"
    transcript: str = ""  # already redacted
    secrets: int = 0
    unreadable_parts: int = 0
    redacted_image_data_uri: str | None = None
    boxes: list[dict] = Field(default_factory=list)


class LintIssue(BaseModel):
    code: str
    level: Literal["error", "warn", "info"]
    message: str


class VerifiedFinding(BaseModel):
    id: str
    title: str
    affected_asset: str = ""
    summary: str = ""
    description: str = ""
    steps_to_reproduce: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: list[str] = Field(default_factory=list)
    severity: Severity = "Unrated"
    severity_source: Literal["tester", "model_metrics", "none"] = "none"
    cvss_vector: str | None = None
    cvss_score: float | None = None
    cvss_rationale: str = ""
    confidence: Confidence = "needs_more_evidence"
    cwe: list[CweRef] = Field(default_factory=list)
    cve: list[CveRef] = Field(default_factory=list)
    removed_ids: list[RemovedId] = Field(default_factory=list)
    claims: list[ClaimResult] = Field(default_factory=list)
    secrets: list[SecretPublic] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    lint: list[LintIssue] = Field(default_factory=list)
    status: Status = "needs_review"
    timings_ms: dict[str, int] = Field(default_factory=dict)


class Engagement(BaseModel):
    client: str = "Client (demo)"
    project: str = "Security assessment"
    tester: str = ""
    reviewed_by: str = ""
    date_range: str = ""
    scope: list[str] = Field(default_factory=list)
    methodology: str = "OWASP WSTG"


class Report(BaseModel):
    engagement: Engagement
    findings: list[VerifiedFinding]
    executive_summary: str = ""
    severity_counts: dict[str, int] = Field(default_factory=dict)
    generated_at: str = ""
    tool: dict[str, str] = Field(default_factory=dict)
