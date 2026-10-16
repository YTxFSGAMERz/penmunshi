"""Render the demo evidence text into terminal-style PNG screenshots.

Gives you real images for a Day-1 smoke test of the vision pass, without touching any real
client material. Everything is fictional (shop.acme.test) and the keys are the public AWS
documentation examples.

    python scripts/make_demo_screenshots.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1] / "examples" / "acme-demo" / "findings"
FONTS = [
    "C:/Windows/Fonts/consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
]

SHOTS: dict[str, dict[str, str]] = {
    "001-sqli-login": {
        "burp-login-sqli.png": (
            "POST /login HTTP/1.1\n"
            "Host: shop.acme.test\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "\n"
            "username=%27+OR+%271%27%3D%271%27+--+-&password=x\n"
            "\n"
            "HTTP/1.1 302 Found\n"
            "Location: /admin/dashboard\n"
            "Server: nginx/1.24.0"
        ),
        "mysql-error.png": (
            "You have an error in your SQL syntax; check the manual that corresponds\n"
            "to your MySQL server version for the right syntax to use near ''' at line 1"
        ),
    },
    "002-exposed-git": {
        "git-head.png": (
            "$ curl -s https://shop.acme.test/.git/HEAD\n"
            "ref: refs/heads/main\n"
            "$ git-dumper https://shop.acme.test/.git/ ./dump\n"
            "[-] Fetching common files\n"
            "[-] Finished: 214 objects recovered"
        ),
        "config-history.png": (
            "$ git show 4f2a9c1:config/aws.ini\n"
            "[aws]\n"
            "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "region = ap-south-1"
        ),
    },
    "003-idor-invoices": {
        "invoice-1043.png": (
            "GET /api/invoices/1043 HTTP/1.1\n"
            "Host: shop.acme.test\n"
            "\n"
            "HTTP/1.1 200 OK\n"
            "Content-Type: application/json\n"
            "\n"
            '{"id":1043,"customer":"Rahul M","email":"rahul.m@acme-shop.in","total":"4200.00"}'
        ),
    },
}


def font(size: int = 20) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in FONTS:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def render(text: str, path: Path) -> None:
    f = font()
    lines = text.split("\n")
    width = max(int(f.getlength(line)) for line in lines) + 48
    height = 28 * len(lines) + 40
    img = Image.new("RGB", (max(width, 640), height), (15, 20, 26))
    draw = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        draw.text((24, 20 + 28 * i), line, font=f, fill=(222, 228, 234))
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, optimize=True)


def main() -> None:
    for finding, shots in SHOTS.items():
        for name, text in shots.items():
            render(text, ROOT / finding / "evidence" / name)
            print("wrote", finding, name)


if __name__ == "__main__":
    main()
