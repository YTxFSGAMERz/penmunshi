"""Capture real UI screenshots for documentation and the DEV challenge post.
Uses Playwright with headless Edge at 1280x800 and 390x844.
"""

from __future__ import annotations

import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ASSETS = Path("docs/assets")
ASSETS.mkdir(parents=True, exist_ok=True)

EDGE_PATH = "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
DEMO_DIR = Path("examples/acme-demo/findings/002-exposed-git")


def capture():
    notes_text = (DEMO_DIR / "notes.md").read_text(encoding="utf-8")
    screenshot_path = DEMO_DIR / "evidence" / "config-history.png"

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=EDGE_PATH, headless=True)

        # 1. Capture screen at 1280x800
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        page.goto("http://127.0.0.1:8765")
        page.wait_for_selector("#status.ok", timeout=10000)
        time.sleep(1)
        page.screenshot(path=str(ASSETS / "01-capture-1280x800.png"))
        print("Captured 01-capture-1280x800.png")

        # Mobile capture screen at 390x844
        page_mobile = browser.new_page(viewport={"width": 390, "height": 844})
        page_mobile.goto("http://127.0.0.1:8765")
        page_mobile.wait_for_selector("#status.ok", timeout=10000)
        time.sleep(1)
        page_mobile.screenshot(path=str(ASSETS / "01-capture-390x844.png"))
        print("Captured 01-capture-390x844.png")
        page_mobile.close()

        # 2. Fill notes and upload screenshot on desktop page
        page.fill("#notes", notes_text)
        page.set_input_files("#file", str(screenshot_path))
        time.sleep(1)

        # Click analyze finding
        page.click("#btn-analyze")
        print("Waiting for real Gemma analysis...")
        page.wait_for_selector("#draft:not([hidden])", timeout=120000)
        time.sleep(2)

        # Scroll to draft
        page.locator("#draft").scroll_into_view_if_needed()
        time.sleep(1)
        page.screenshot(path=str(ASSETS / "02-draft-1280x800.png"), full_page=True)
        print("Captured 02-draft-1280x800.png")

        # Toggle mask inspection outline if available
        inspect_btn = page.locator("#draft button:has-text('Inspect mask boxes')")
        if inspect_btn.count() > 0:
            inspect_btn.first.click()
            time.sleep(1)
            page.screenshot(path=str(ASSETS / "02-draft-inspect-masks.png"))
            print("Captured 02-draft-inspect-masks.png")

        # Click a claim row to demonstrate claim-to-evidence quote highlighting
        claim_row = page.locator("#draft table.claims tbody tr.clickable")
        if claim_row.count() > 0:
            claim_row.first.click()
            time.sleep(1)
            page.screenshot(path=str(ASSETS / "02-claim-highlighted.png"))
            print("Captured 02-claim-highlighted.png")

        # Add to report
        page.click("#draft button:has-text('Add to report')")
        time.sleep(1)

        # Draft summary
        page.click("#btn-summary")
        print("Drafting summary...")
        page.wait_for_function("document.getElementById('summary').value.length > 5", timeout=60000)
        time.sleep(1)

        # Render and capture exported HTML report
        # We can fetch the exported HTML report from the export endpoint and load it
        res = page.request.post(
            "http://127.0.0.1:8765/api/export?fmt=html",
            data={
                "engagement": {
                    "client": "Acme Retail Ltd",
                    "project": "E-Commerce Security Assessment",
                    "tester": "Lead Security Engineer",
                    "date_range": "14 Oct - 17 Oct 2026",
                    "methodology": "OWASP WSTG v4.2",
                    "scope": ["https://shop.acme.test"],
                    "reviewed_by": "Pending Final Signoff",
                },
                "findings": page.evaluate("() => state.basket"),
                "executive_summary": page.input_value("#summary"),
            },
        )
        html_report = res.text()
        report_file = ASSETS / "report-preview.html"
        report_file.write_text(html_report, encoding="utf-8")

        report_page = browser.new_page(viewport={"width": 1000, "height": 1200})
        report_page.goto(f"file:///{report_file.resolve().as_posix()}")
        time.sleep(1)
        report_page.screenshot(path=str(ASSETS / "03-report-html.png"), full_page=True)
        print("Captured 03-report-html.png")

        browser.close()
        print("All assets captured successfully in docs/assets/")


if __name__ == "__main__":
    capture()
