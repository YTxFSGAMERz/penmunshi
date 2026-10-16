import io
from pathlib import Path

import pytest
from PIL import Image, ImageChops, ImageDraw, ImageFont

from penmunshi.verify.verhoeff import check_digit

rapidocr = pytest.importorskip("rapidocr_onnxruntime")
from penmunshi.verify.redact_image import is_ocr_available, redact_screenshot  # noqa: E402

FONTS = [
    "C:/Windows/Fonts/consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
]


def _get_font(size: int = 20) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in FONTS:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _render_image(text: str, bg: tuple[int, int, int] = (15, 20, 26), fg: tuple[int, int, int] = (222, 228, 234)) -> bytes:
    f = _get_font()
    lines = text.split("\n")
    width = max(int(f.getlength(line)) for line in lines) + 80
    height = 32 * len(lines) + 60
    img = Image.new("RGB", (max(width, 700), max(height, 240)), bg)
    draw = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        draw.text((28, 24 + 32 * i), line, font=f, fill=fg)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_ocr_availability():
    assert is_ocr_available() is True


def test_redact_no_secrets():
    safe_text = "GET /index.html HTTP/1.1\nHost: example.test\nStatus: 200 OK\nListing directory /var/www/html"
    raw_bytes = _render_image(safe_text)
    res = redact_screenshot(raw_bytes)
    assert res.masked_count == 0
    assert len(res.boxes) == 0
    assert res.re_ocr_verified is True

    # Identical pixels: diff bounding box must be None
    orig_img = Image.open(io.BytesIO(raw_bytes))
    red_img = Image.open(io.BytesIO(res.redacted_png))
    diff = ImageChops.difference(orig_img, red_img)
    assert diff.getbbox() is None


def test_redact_aws_credentials():
    aws_text = (
        "[aws]\n"
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "region = ap-south-1"
    )
    raw_bytes = _render_image(aws_text)
    known = ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]
    res = redact_screenshot(raw_bytes, known_values=known)

    assert res.masked_count >= 1
    assert res.re_ocr_verified is True
    assert res.data_uri.startswith("data:image/png;base64,")

    # Inspect image: box pixels should be black (0, 0, 0)
    red_img = Image.open(io.BytesIO(res.redacted_png))
    for b in res.boxes:
        sample_x = b.x + b.w // 2
        sample_y = b.y + b.h // 2
        assert red_img.getpixel((sample_x, sample_y)) == (0, 0, 0)

    # Outside pixels (e.g. top-left corner) should remain original background (15, 20, 26)
    assert red_img.getpixel((5, 5)) == (15, 20, 26)


def test_redact_jwt_token():
    text = (
        "HTTP/1.1 200 OK\n"
        "Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\n"
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\n"
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c; Path=/; Secure\n"
        "Content-Type: application/json"
    )
    raw_bytes = _render_image(text)
    res = redact_screenshot(raw_bytes)

    assert res.masked_count >= 1
    assert res.re_ocr_verified is True


def test_redact_password_and_email():
    text = (
        "POST /api/login HTTP/1.1\n"
        '{"user": "alice@corp.internal", "password": "SuperSecretPassword123"}'
    )
    raw_bytes = _render_image(text)
    res = redact_screenshot(raw_bytes, known_values=["SuperSecretPassword123"])

    assert res.masked_count >= 1
    assert res.re_ocr_verified is True


def test_redact_aadhaar_with_verhoeff():
    base = "23456789012"
    aadhaar = base + check_digit(base)
    text = f"Customer Profile: John Doe\nAadhaar: {aadhaar[:4]} {aadhaar[4:8]} {aadhaar[8:]}\nCity: Mumbai"
    raw_bytes = _render_image(text)
    res = redact_screenshot(raw_bytes)

    assert res.masked_count >= 1
    assert res.re_ocr_verified is True
