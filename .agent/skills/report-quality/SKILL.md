---
name: report-quality
description: What a client-ready VAPT report must contain and how PenMunshi renders it: finding anatomy, severity conventions, executive summary rules, DOCX/HTML polish (cover, table of contents, headers, page numbers, print CSS), retest/diff mode and importers for Nmap, Burp and Nessus. Use whenever you work on src/penmunshi/report/, lint rules about report quality, templates, exports, or the retest and import features.
---

# Report quality

Buyers of VAPT reports judge samples before they hire. A common complaint is a scanner export dropped into a template. Our lint rules exist to prevent that. See `references/finding-anatomy.md` for the checklist.

## Per finding (the render must show all of these)
Title naming the weakness and the asset; severity with the CVSS vector and a note that software computed it; affected asset; description; **evidence** (redacted screenshot or transcript); **steps to reproduce** a client engineer can follow in ten minutes; **business impact** in plain language; **remediation** that is concrete; references (CWE id and name from the catalog; CVE only when sourced); status/confidence.

## Per report
Cover (client, project, tester, dates, methodology, scope, reviewer), the AI-assisted-draft banner, executive summary without numbers in the prose (counts come from the severity table), findings overview sorted by severity then score, findings, verification appendix. Never remove the verification appendix: it is the trust feature.

## Upgrades worth doing (in order)
1. Embed redacted screenshots (needs `screenshot-redaction`).
2. DOCX polish: cover page, table of contents field, header/footer with page numbers (python-docx XML fields), consistent table styles, severity colour chips as shaded cells.
3. HTML print CSS: `@page` margins, running header, page-break rules. Document "Print to PDF" in the README rather than adding a heavy PDF dependency.
4. **Retest mode**: `penmunshi retest old/report.json new/report.json` outputs a table (resolved, open, regressed, new) matched by title+asset similarity, deterministic and tested.
5. **Importers** (deterministic parsers, no model): Nmap XML, Burp XML issues, Nessus CSV, nuclei JSONL. Each produces finding folders (`notes.md` + `tool_output.txt`) so testers start from tool output instead of a blank page. Test each with a small fictional sample.

## Rules
- All text from findings goes through Jinja autoescape (HTML) or python-docx text (DOCX). Never mark finding text `|safe`.
- Severity labels use `label()` ("None" is shown as "Informational").
- Rendering must be deterministic for the same `Report` (tests compare structure, not timestamps).
