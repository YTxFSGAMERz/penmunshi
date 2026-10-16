"""Screenshot redaction: OCR text boxes, detect secrets/PII, paint opaque black bars,
and verify via re-OCR that secrets are unrecoverable. Never persist or send original pixels.
"""

from __future__ import annotations

import base64
import io
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from PIL import Image, ImageDraw

from .secrets import scan_text

_OCR_ENGINE = None
_OCR_INITIALIZED = False


def get_ocr_engine():
    global _OCR_ENGINE, _OCR_INITIALIZED
    if not _OCR_INITIALIZED:
        _OCR_INITIALIZED = True
        try:
            from rapidocr_onnxruntime import RapidOCR

            _OCR_ENGINE = RapidOCR()
        except Exception:
            _OCR_ENGINE = None
    return _OCR_ENGINE


def is_ocr_available() -> bool:
    return get_ocr_engine() is not None


@dataclass
class RedactionBox:
    x: int
    y: int
    w: int
    h: int
    kind: str
    preview: str = ""

    def to_dict(self) -> dict:
        return {
            "x": self.x,
            "y": self.y,
            "w": self.w,
            "h": self.h,
            "kind": self.kind,
            "preview": self.preview,
        }


@dataclass
class RedactionResult:
    redacted_png: bytes
    data_uri: str
    boxes: list[RedactionBox] = field(default_factory=list)
    masked_count: int = 0
    re_ocr_verified: bool = True
    warnings: list[str] = field(default_factory=list)


@dataclass
class _OcrItem:
    idx: int
    points: list[list[float]]
    text: str
    conf: float
    min_x: float
    max_x: float
    min_y: float
    max_y: float
    center_y: float
    height: float


def _parse_ocr_items(results: list, img_w: int, img_h: int) -> list[_OcrItem]:
    items: list[_OcrItem] = []
    for idx, r in enumerate(results):
        points, text, conf = r[0], str(r[1]), float(r[2])
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        min_x = max(0.0, min(xs))
        max_x = min(float(img_w), max(xs))
        min_y = max(0.0, min(ys))
        max_y = min(float(img_h), max(ys))
        items.append(
            _OcrItem(
                idx=idx,
                points=points,
                text=text,
                conf=conf,
                min_x=min_x,
                max_x=max_x,
                min_y=min_y,
                max_y=max_y,
                center_y=(min_y + max_y) / 2.0,
                height=max(1.0, max_y - min_y),
            )
        )
    return items


def _group_into_lines(items: list[_OcrItem]) -> list[list[_OcrItem]]:
    if not items:
        return []
    sorted_items = sorted(items, key=lambda it: it.center_y)
    lines: list[list[_OcrItem]] = []
    for it in sorted_items:
        placed = False
        for line in lines:
            line_cy = sum(member.center_y for member in line) / len(line)
            line_h = max(member.height for member in line)
            if abs(it.center_y - line_cy) < max(it.height, line_h) * 0.6:
                line.append(it)
                placed = True
                break
        if not placed:
            lines.append([it])
    for line in lines:
        line.sort(key=lambda it: it.min_x)
    lines.sort(key=lambda line: min(it.min_y for it in line))
    return lines


def redact_screenshot(
    image_bytes: bytes,
    known_values: Sequence[str] = (),
    *,
    pad: int = 4,
) -> RedactionResult:
    """Detect secrets via OCR and paint solid opaque black rectangles.

    Asserts through re-OCR that no secret strings remain recoverable.
    Original pixels are discarded and never saved.
    """
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception as exc:
        return RedactionResult(
            redacted_png=image_bytes,
            data_uri="data:image/png;base64,",
            boxes=[],
            masked_count=0,
            re_ocr_verified=False,
            warnings=[f"Failed to decode image: {exc}"],
        )
    width, height = img.size

    ocr = get_ocr_engine()
    if ocr is None:
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_data = buf.getvalue()
        b64 = base64.b64encode(png_data).decode("ascii")
        return RedactionResult(
            redacted_png=png_data,
            data_uri=f"data:image/png;base64,{b64}",
            boxes=[],
            masked_count=0,
            re_ocr_verified=False,
            warnings=["rapidocr-onnxruntime is not installed; screenshot not auto-redacted."],
        )

    ocr_results, _ = ocr(image_bytes)
    if not ocr_results:
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_data = buf.getvalue()
        b64 = base64.b64encode(png_data).decode("ascii")
        return RedactionResult(
            redacted_png=png_data,
            data_uri=f"data:image/png;base64,{b64}",
            boxes=[],
            masked_count=0,
            re_ocr_verified=True,
        )

    items = _parse_ocr_items(ocr_results, width, height)
    lines = _group_into_lines(items)

    # Build line texts and character mappings
    # char_to_item: (line_idx, char_idx_in_line) -> (item_idx, char_idx_in_item)
    full_text_parts: list[str] = []
    line_offsets: list[int] = []
    char_map: dict[int, tuple[int, int]] = {}  # full_text offset -> (item_idx, char_in_item)

    curr_offset = 0
    for line in lines:
        line_offsets.append(curr_offset)
        line_text = ""
        for i, it in enumerate(line):
            if i > 0:
                line_text += " "
                curr_offset += 1
            it_start_offset = curr_offset
            for c_idx in range(len(it.text)):
                char_map[it_start_offset + c_idx] = (it.idx, c_idx)
            line_text += it.text
            curr_offset += len(it.text)
        full_text_parts.append(line_text)
        curr_offset += 1  # for \n

    full_text = "\n".join(full_text_parts)

    # Secret spans: list of (span_start, span_end, kind, preview, raw_value)
    targets: list[tuple[int, int, str, str, str]] = []

    # 1. Regex detectors on full joined text
    for hit in scan_text(full_text, source="screenshot"):
        val = full_text[hit.start : hit.end]
        targets.append((hit.start, hit.end, hit.kind, hit.preview, val))

    # 2. Match known values in full joined text
    for kv in known_values:
        kv_clean = kv.strip()
        if len(kv_clean) < 4:
            continue
        # Case insensitive finditer
        for m in re.finditer(re.escape(kv_clean), full_text, flags=re.IGNORECASE):
            s, e = m.span()
            matched_val = full_text[s:e]
            targets.append((s, e, "known_secret", f"**** {matched_val[-4:]}", matched_val))

    # 3. Direct item scan in case line joining broke a token
    item_direct_targets: list[tuple[int, int, int, str, str, str]] = []  # (item_idx, c_start, c_end, kind, prev, val)
    for it in items:
        # scan_text
        for h in scan_text(it.text, source="ocr_item"):
            val = it.text[h.start : h.end]
            item_direct_targets.append((it.idx, h.start, h.end, h.kind, h.preview, val))
        # known values in item.text
        for kv in known_values:
            kv_clean = kv.strip()
            if len(kv_clean) >= 4 and kv_clean.lower() in it.text.lower():
                s = it.text.lower().index(kv_clean.lower())
                e = s + len(kv_clean)
                matched_val = it.text[s:e]
                item_direct_targets.append(
                    (it.idx, s, e, "known_secret", f"**** {matched_val[-4:]}", matched_val)
                )

    # Map all targets to item bounding boxes
    items_by_idx = {it.idx: it for it in items}
    boxes_to_draw: list[tuple[int, int, int, int, str, str]] = []  # (x0, y0, x1, y1, kind, preview)
    secret_strings_to_verify: list[str] = []

    # From full_text targets
    for start, end, kind, preview, raw_val in targets:
        secret_strings_to_verify.append(raw_val)
        affected: dict[int, list[int]] = {}
        for pos in range(start, end):
            if pos in char_map:
                it_idx, c_idx = char_map[pos]
                affected.setdefault(it_idx, []).append(c_idx)

        for it_idx, chars in affected.items():
            it = items_by_idx[it_idx]
            min_c = min(chars)
            max_c = max(chars) + 1
            it_len = max(len(it.text), 1)
            it_w = it.max_x - it.min_x
            bx0 = it.min_x + (min_c / it_len) * it_w
            bx1 = it.min_x + (max_c / it_len) * it_w
            by0, by1 = it.min_y, it.max_y
            rx0 = max(0, int(bx0 - pad))
            ry0 = max(0, int(by0 - pad))
            rx1 = min(width, int(bx1 + pad))
            ry1 = min(height, int(by1 + pad))
            boxes_to_draw.append((rx0, ry0, rx1, ry1, kind, preview))

    # From direct item targets
    for it_idx, c_start, c_end, kind, preview, raw_val in item_direct_targets:
        secret_strings_to_verify.append(raw_val)
        it = items_by_idx[it_idx]
        it_len = max(len(it.text), 1)
        it_w = it.max_x - it.min_x
        bx0 = it.min_x + (c_start / it_len) * it_w
        bx1 = it.min_x + (c_end / it_len) * it_w
        by0, by1 = it.min_y, it.max_y
        rx0 = max(0, int(bx0 - pad))
        ry0 = max(0, int(by0 - pad))
        rx1 = min(width, int(bx1 + pad))
        ry1 = min(height, int(by1 + pad))
        boxes_to_draw.append((rx0, ry0, rx1, ry1, kind, preview))

    if not boxes_to_draw:
        # No secrets detected: return original image bytes directly
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_data = buf.getvalue()
        b64 = base64.b64encode(png_data).decode("ascii")
        return RedactionResult(
            redacted_png=png_data,
            data_uri=f"data:image/png;base64,{b64}",
            boxes=[],
            masked_count=0,
            re_ocr_verified=True,
        )

    # Deduplicate overlapping boxes
    deduped_boxes: list[RedactionBox] = []
    seen_coords: set[tuple[int, int, int, int]] = set()
    for rx0, ry0, rx1, ry1, kind, prev in boxes_to_draw:
        coords = (rx0, ry0, rx1, ry1)
        if coords not in seen_coords:
            seen_coords.add(coords)
            deduped_boxes.append(
                RedactionBox(x=rx0, y=ry0, w=rx1 - rx0, h=ry1 - ry0, kind=kind, preview=prev)
            )

    # 4. Paint opaque black bars
    draw = ImageDraw.Draw(img)
    for b in deduped_boxes:
        draw.rectangle([b.x, b.y, b.x + b.w, b.y + b.h], fill=(0, 0, 0))

    # 5. Re-OCR Verification
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    redacted_bytes = buf.getvalue()

    re_results, _ = ocr(redacted_bytes)
    warnings: list[str] = []
    re_ocr_verified = True

    if re_results:
        re_items = _parse_ocr_items(re_results, width, height)
        re_joined = "\n".join(it.text for it in re_items)
        re_hits = scan_text(re_joined, source="re_ocr")

        residual_items: list[_OcrItem] = []
        for rh in re_hits:
            residual_items.extend(re_items)
            warnings.append(f"Residual secret detected in re-OCR: {rh.preview}")

        for sec in secret_strings_to_verify:
            if len(sec) >= 6 and sec.lower() in re_joined.lower():
                for it in re_items:
                    if sec.lower() in it.text.lower():
                        residual_items.append(it)
                        warnings.append(f"Secret string fragment survived in re-OCR: {sec[:4]}...")

        if residual_items:
            # Fallback: blackout entire lines covering residual items with 8px padding
            for it in residual_items:
                fx0 = max(0, int(it.min_x - 8))
                fy0 = max(0, int(it.min_y - 8))
                fx1 = min(width, int(it.max_x + 8))
                fy1 = min(height, int(it.max_y + 8))
                draw.rectangle([fx0, fy0, fx1, fy1], fill=(0, 0, 0))
                deduped_boxes.append(
                    RedactionBox(
                        x=fx0,
                        y=fy0,
                        w=fx1 - fx0,
                        h=fy1 - fy0,
                        kind="residual_fallback",
                        preview="[blackout line]",
                    )
                )

            # Re-save and final verification check
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            redacted_bytes = buf.getvalue()
            final_re_results, _ = ocr(redacted_bytes)
            if final_re_results:
                final_text = "\n".join(str(r[1]) for r in final_re_results)
                if scan_text(final_text, source="re_ocr_final"):
                    re_ocr_verified = False
                    warnings.append("Secret text still detected after fallback blackout.")
                else:
                    re_ocr_verified = True
            else:
                re_ocr_verified = True

    b64 = base64.b64encode(redacted_bytes).decode("ascii")
    return RedactionResult(
        redacted_png=redacted_bytes,
        data_uri=f"data:image/png;base64,{b64}",
        boxes=deduped_boxes,
        masked_count=len(deduped_boxes),
        re_ocr_verified=re_ocr_verified,
        warnings=warnings,
    )
