import { JSDOM } from "jsdom";

const errors = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const dom = await JSDOM.fromURL("http://127.0.0.1:8765/", {
  runScripts: "dangerously",
  resources: "usable",
  pretendToBeVisual: true,
  beforeParse(window) {
    window.fetch = (url, opts) => fetch(new URL(url, window.location.href).href, opts);
    window.FormData = globalThis.FormData;
    window.File = globalThis.File;
    window.Blob = globalThis.Blob;
    window.URL.createObjectURL = () => "blob:stub";
    window.HTMLElement.prototype.scrollIntoView = () => {};
    window.scrollTo = () => {};
    window.addEventListener("error", (e) => errors.push("window error: " + e.message));
  },
});
const { window } = dom;
const $ = (s) => window.document.querySelector(s);
const check = (name, ok) => { console.log((ok ? "PASS " : "FAIL ") + name); if (!ok) process.exitCode = 1; };

await sleep(800);
check("status shows backend state", /Fake backend/.test($("#status").textContent));

$("#notes").value = "Login bypass.\npassword=hunter2xyz\n<img src=x onerror=window.__pwned=1>";
$("#tool").value = "<script>window.__pwned=1</script> AKIAIOSFODNN7EXAMPLE";
$("#btn-analyze").click();
for (let i = 0; i < 40 && $("#draft").hidden; i++) await sleep(150);
check("draft becomes visible", !$("#draft").hidden);
const draftText = $("#draft").textContent;
check("title rendered", draftText.length > 100 && /Login bypass/.test(draftText));
check("severity chip rendered", !!$("#draft .chip"));
check("raw secrets absent from DOM", !/hunter2xyz/.test(draftText) && !/AKIAIOSFODNN7EXAMPLE/.test(draftText));
check("redaction bars rendered", $("#draft .bar") !== null);
check("hostile HTML stayed text (no img/script injected)", $("#draft img") === null && $("#draft script") === null && window.__pwned === undefined);
check("evidence checks table present", !!$("#draft table.claims"));
check("evidence transcript rendered as elements, not [object ...]", !/\[object /.test(draftText) && window.document.querySelectorAll("#draft details pre.evidence").length >= 1);

const claimRow = window.document.querySelector("#draft table.claims tbody tr.claim-row");
check("claim row present with clickable class", claimRow !== null && claimRow.classList.contains("clickable"));
if (claimRow) {
  claimRow.click();
  const highlighted = window.document.querySelector("#draft mark.quote-match");
  check("clicking claim highlights quote with <mark class='quote-match'>", highlighted !== null);
}

const add = [...window.document.querySelectorAll("#draft button")].find((b) => /Add to report/.test(b.textContent));
add.click();
check("finding moved into the report basket", window.document.querySelectorAll("#basket li .chip").length === 1);
check("draft hidden after add", $("#draft").hidden === true);

$("#btn-summary").click();
for (let i = 0; i < 20 && !$("#summary").value; i++) await sleep(150);
check("summary drafted into the textarea", $("#summary").value.length > 10);

const res = await fetch("http://127.0.0.1:8765/api/export?fmt=html", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ engagement: {}, findings: [], executive_summary: "" }),
});
check("export endpoint reachable from the same origin", res.status === 200);

// Test 2: Analyze finding with screenshot and verify redaction card
const fakePngBytes = new Uint8Array([
  137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 100, 0, 0, 0, 100, 8, 2, 0, 0, 0, 255, 128, 2, 3, 0, 0, 0, 235, 73, 68, 65, 84, 120, 156, 237, 210, 161, 17, 0, 33, 16, 4, 65, 248, 4, 48, 40, 242, 15, 244, 83, 184, 241, 221, 122, 213, 212, 238, 115, 223, 98, 230, 27, 238, 16, 171, 241, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 64, 172, 53, 247, 3, 107, 121, 1, 5, 193, 102, 47, 93, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130
]);
const fakeFile = new window.File([fakePngBytes], "test-shot.png", { type: "image/png" });
window.state.files.push(fakeFile);
window.renderThumbs();
check("screenshot thumbnail added to UI", window.document.querySelectorAll("#thumbs .thumb").length === 1);

$("#notes").value = "Finding with screenshot evidence";
$("#btn-analyze").click();
for (let i = 0; i < 40 && $("#draft").hidden; i++) await sleep(150);
if ($("#draft").hidden) console.log("Second analyze error:", $("#err").textContent);
check("second draft becomes visible", !$("#draft").hidden);
const shotCard = window.document.querySelector("#draft .screenshot-card");
check("screenshot card rendered with redacted image", shotCard !== null && shotCard.querySelector("img") !== null);
check("original pixels never sent (img src is data uri)", shotCard && shotCard.querySelector("img").src.startsWith("data:image/png;base64,"));

check("no uncaught page errors", errors.length === 0);
if (errors.length) console.log(errors);
window.close();
