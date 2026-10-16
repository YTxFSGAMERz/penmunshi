"""Prompts. Keep them short, explicit, and testable. Every rule here has a matching
deterministic check in penmunshi/verify - the prompt asks nicely, the code enforces."""

from __future__ import annotations

from ..models import FindingDraft
from .schema import build_schema

TRANSCRIBE_SYSTEM = (
    "You are an OCR transcriber for security-testing screenshots: terminal output, Burp Suite, "
    "browser dev-tools, HTTP requests and responses, source code. Copy the visible text exactly, "
    "keeping line breaks, hosts, paths, status codes, headers and payloads. Do not summarise, "
    "explain, correct or infer. If part of the image is unreadable write [unreadable] in its "
    "place. Never invent text. Reply with JSON only."
)
TRANSCRIBE_USER = "Transcribe this screenshot exactly."
TRANSCRIBE_SCHEMA = {
    "type": "object",
    "properties": {
        "transcript": {"type": "string"},
        "unreadable_parts": {"type": "integer"},
    },
    "required": ["transcript", "unreadable_parts"],
    "additionalProperties": False,
}

DRAFT_SYSTEM = """You are a senior penetration tester drafting ONE finding for a client-ready VAPT report.
You receive the tester's raw notes plus text transcribed from their evidence screenshots.
Sensitive values were replaced with [REDACTED:<kind>] markers before you saw them. Keep the markers and never guess the original value.

Rules (software checks every one of them):
1. Use ONLY facts present in the notes or evidence. Never invent hosts, endpoints, credentials, versions, CVE IDs or results.
2. Every entry in "claims" is one factual statement from your write-up. Set "evidence_ref" to the evidence file name, "tool_output" or "notes", and set "quote" to a SHORT verbatim excerpt (max 200 characters) copied from that source. If you cannot quote it, do not claim it.
3. CVSS: choose the CVSS v3.1 base metric letters that fit the evidence. Never write a numeric score or a severity label; software computes them. Put your reasoning in "cvss_rationale" (one or two sentences).
4. CWE: give the most specific matching CWE number(s) as digits only, for example "89". CVE: include a CVE ID only if it is written in the notes or evidence, otherwise leave the list empty.
5. "steps_to_reproduce": short imperative steps a client engineer can follow in ten minutes, using only endpoints, parameters and payloads from the notes or evidence.
6. "impact": plain-language business impact (what an attacker gains). "remediation": concrete, actionable fixes.
7. If the evidence is thin or ambiguous, set "confidence" to "needs_more_evidence" and say what is missing in "description". Do not smooth over gaps.
Reply with JSON that matches the schema. No markdown, no commentary."""

SUMMARY_SYSTEM = (
    "You write the executive summary of a penetration test report for non-technical managers. "
    "Write at most two short paragraphs. Do not state any numbers or counts (software inserts "
    "the severity table). Use only the findings provided (title, severity, one-line summary). "
    "No exploit details and no marketing language. Reply with JSON only."
)
SUMMARY_SCHEMA = {
    "type": "object",
    "properties": {"summary": {"type": "string"}},
    "required": ["summary"],
    "additionalProperties": False,
}

DRAFT_SCHEMA = build_schema(FindingDraft)


def build_draft_prompt(finding_id: str, sources: dict[str, str]) -> str:
    """`sources` maps a reference name (notes, tool_output, shot1.png...) to REDACTED text."""
    parts = [f"FINDING ID: {finding_id}"]
    notes = sources.get("notes", "")
    parts.append(f"TESTER NOTES:\n<<<\n{notes.strip() or '(none)'}\n>>>")
    for ref, text in sources.items():
        if ref == "notes":
            continue
        label = "TOOL OUTPUT" if ref == "tool_output" else f"EVIDENCE [{ref}]"
        parts.append(f"{label}:\n<<<\n{text.strip() or '(empty)'}\n>>>")
    return "\n\n".join(parts)
