"""Deterministic Burp Suite XML parser. Converts exported scanner issues to finding folders."""

from __future__ import annotations

import base64
from pathlib import Path

try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

from .common import ImportedFinding, clean_html_text, slugify


def _decode_req_resp(elem: ET.Element | None) -> str:
    if elem is None or elem.text is None:
        return ""
    text = elem.text.strip()
    if elem.get("base64") == "true":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return text
    return text


def parse_burp_xml(xml_content: str | bytes) -> list[ImportedFinding]:
    """Parse Burp Suite XML export (<issues>) into a list of ImportedFinding objects."""
    findings: list[ImportedFinding] = []
    if isinstance(xml_content, str):
        xml_content = xml_content.encode("utf-8")

    root = ET.fromstring(xml_content)
    if root.tag != "issues":
        raise ValueError("Not a valid Burp Suite XML output (missing <issues> root tag)")

    for issue in root.findall("issue"):
        name_el = issue.find("name")
        title = name_el.text.strip() if name_el is not None and name_el.text else "Burp Suite Issue"

        host_el = issue.find("host")
        host_str = host_el.text.strip() if host_el is not None and host_el.text else ""

        path_el = issue.find("path")
        path_str = path_el.text.strip() if path_el is not None and path_el.text else ""

        location_el = issue.find("location")
        location_str = location_el.text.strip() if location_el is not None and location_el.text else ""

        asset = f"{host_str}{path_str}" if host_str else (path_str or location_str or "Web Application")

        severity_el = issue.find("severity")
        severity = severity_el.text.strip() if severity_el is not None and severity_el.text else "Information"
        if severity.lower() == "information":
            severity = "Low"

        confidence_el = issue.find("confidence")
        confidence_raw = confidence_el.text.strip().lower() if confidence_el is not None and confidence_el.text else "likely"
        confidence_map = {
            "certain": "confirmed",
            "firm": "likely",
            "tentative": "needs_more_evidence",
        }
        confidence = confidence_map.get(confidence_raw, "likely")

        detail_el = issue.find("issueDetail")
        detail = clean_html_text(detail_el.text) if detail_el is not None and detail_el.text else ""

        bg_el = issue.find("issueBackground")
        background = clean_html_text(bg_el.text) if bg_el is not None and bg_el.text else ""

        remedy_el = issue.find("remediationBackground")
        remediation = clean_html_text(remedy_el.text) if remedy_el is not None and remedy_el.text else ""

        # Extract requests and responses
        req_resp_blocks: list[str] = []
        for rr in issue.findall("requestresponse"):
            req_text = _decode_req_resp(rr.find("request"))
            resp_text = _decode_req_resp(rr.find("response"))
            if req_text or resp_text:
                block = []
                if req_text:
                    block.append("=== REQUEST ===\n" + req_text)
                if resp_text:
                    block.append("=== RESPONSE ===\n" + resp_text)
                req_resp_blocks.append("\n\n".join(block))

        tool_output = "\n\n" + ("=" * 40 + "\n\n").join(req_resp_blocks) if req_resp_blocks else detail

        slug = slugify(f"{title}-{path_str or location_str}")

        notes = f"""# {title} in {asset}

- **Asset**: `{asset}`
- **Location**: `{location_str or path_str}`
- **Severity**: `{severity}`
- **Confidence**: `{confidence}`

## Details
{detail or background or 'Vulnerability detected by Burp Suite Scanner.'}

## Remediation Guidance
{remediation or 'Review application input validation and context-aware sanitization.'}
"""

        findings.append(
            ImportedFinding(
                slug=slug,
                title=f"{title} in {asset}",
                asset=asset,
                notes=notes,
                tool_output=tool_output,
                severity=severity,
                confidence=confidence,
            )
        )

    return findings


def import_burp(file_path: Path | str, out_dir: Path | str) -> list[Path]:
    """Parse Burp Suite XML file and write findings to output directory."""
    path = Path(file_path)
    xml_data = path.read_text(encoding="utf-8")
    findings = parse_burp_xml(xml_data)
    from .common import write_imported_findings

    return write_imported_findings(findings, Path(out_dir))
