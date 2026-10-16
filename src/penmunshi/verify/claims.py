"""Quote-or-it-didn't-happen: every claim must quote its evidence, and the quote must exist."""

from __future__ import annotations

import re
import unicodedata
from difflib import SequenceMatcher

from ..models import ClaimDraft, ClaimResult

THRESHOLD = 0.85
MIN_QUOTE_CHARS = 8


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKC", s or "").lower()
    s = re.sub(r"[\"'`\u201c\u201d\u2018\u2019]", "", s)
    return re.sub(r"\s+", " ", s).strip()


def match_score(quote: str, source: str) -> float:
    """1.0 for an exact (whitespace/case-insensitive) substring, else best fuzzy window."""
    q, s = _norm(quote), _norm(source)
    if not q or not s:
        return 0.0
    if q in s:
        return 1.0
    n = len(q)
    if n > len(s):
        return round(SequenceMatcher(None, q, s, autojunk=False).ratio(), 3)
    best = 0.0
    step = max(1, n // 6)
    starts = list(range(0, len(s) - n + 1, step)) + [len(s) - n]
    for start in starts:
        best = max(best, SequenceMatcher(None, q, s[start : start + n], autojunk=False).ratio())
        if best >= 0.99:
            break
    return round(best, 3)


def resolve_ref(ref: str, sources: dict[str, str]) -> str | None:
    if ref in sources:
        return ref
    lowered = {k.lower(): k for k in sources}
    r = (ref or "").strip().lower().replace("\\", "/")
    for candidate in (r, r.split("/")[-1], r.replace(" ", "_"), r.replace("-", "_")):
        if candidate in lowered:
            return lowered[candidate]
    return None


def find_quote_offsets(quote: str, source: str, threshold: float = THRESHOLD) -> tuple[int | None, int | None]:
    if not quote or not source:
        return None, None
    q_clean = quote.strip()
    idx = source.find(q_clean)
    if idx != -1:
        return idx, idx + len(q_clean)
    idx_lower = source.lower().find(q_clean.lower())
    if idx_lower != -1:
        return idx_lower, idx_lower + len(q_clean)
    words = [re.escape(w) for w in q_clean.split() if w]
    if words:
        pat = r"\s+".join(words)
        m = re.search(pat, source, re.IGNORECASE)
        if m:
            return m.start(), m.end()
    n = len(q_clean)
    best_ratio = 0.0
    best_span: tuple[int | None, int | None] = (None, None)
    step = max(1, n // 8)
    for start in range(0, max(1, len(source) - n + 1), step):
        chunk = source[start : start + n]
        ratio = SequenceMatcher(None, _norm(q_clean), _norm(chunk), autojunk=False).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
            best_span = (start, start + n)
    if best_ratio >= threshold:
        return best_span
    return None, None


def check_claims(
    claims: list[ClaimDraft], sources: dict[str, str], threshold: float = THRESHOLD
) -> list[ClaimResult]:
    results: list[ClaimResult] = []
    for claim in claims:
        quote = claim.quote.strip()
        ref = resolve_ref(claim.evidence_ref, sources)
        score, found = 0.0, ""
        if ref:
            score = match_score(quote, sources[ref])
            if score >= threshold:
                found = ref
        if not found:  # the model may have cited the wrong source: look everywhere
            for name, text in sources.items():
                sc = match_score(quote, text)
                score = max(score, sc)
                if sc >= threshold:
                    found = name
                    break
        supported = bool(found) and len(_norm(quote)) >= MIN_QUOTE_CHARS
        q_start, q_end = None, None
        if supported and found and found in sources:
            q_start, q_end = find_quote_offsets(quote, sources[found], threshold)
        results.append(
            ClaimResult(
                text=claim.text,
                evidence_ref=ref or claim.evidence_ref,
                quote=quote,
                supported=supported,
                score=score,
                found_in=found,
                quote_start=q_start,
                quote_end=q_end,
            )
        )
    return results
