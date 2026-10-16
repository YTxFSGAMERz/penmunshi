# Finding anatomy checklist (what "good" looks like)

- Title: "<Weakness> in <asset/feature>", no jargon-only titles, no "Vulnerability".
- Severity: band + CVSS vector + score; the vector matches the band; any tester override is labelled.
- Description: what is wrong and where, in 2 to 4 sentences, no marketing.
- Evidence: at least one artefact per claim; secrets masked; each screenshot has a caption.
- Steps: numbered, imperative, uses only real endpoints/parameters/payloads from the engagement.
- Impact: what an attacker gains in business terms (data, money, access, downtime), not just the technique.
- Remediation: concrete (config key, library version, code pattern), plus a verification step for the retest.
- References: CWE id + canonical name; CVE ids only when sourced; OWASP category optional.
- Confidence/status: confirmed, likely, needs more evidence; a human reviewer name on the report.
- Tone: neutral, specific, no blame.
