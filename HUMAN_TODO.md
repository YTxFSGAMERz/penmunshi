# HUMAN_TODO.md — PenMunshi

Actions requiring human action or credentials before the Hacktoberfest Week 2 submission deadline (**Oct 18, 2026, 11:59 PM PDT / Oct 19, 12:29 PM IST**).

---

## 1. Push Code to GitHub
- [ ] Add remote origin:
  ```bash
  git remote add origin https://github.com/YTxFSGAMERz/penmunshi.git
  git push -u origin master
  ```
- [ ] Verify repository is Public and GitHub Actions CI passes.

---

## 2. Deploy Hosted Demo & Claim .tech Domain (Partner Track)
- [ ] Claim your free `.tech` domain via the Hacktoberfest partner portal (`hacktoberfest.com/my`).
- [ ] Enable GitHub Pages on repository settings (point to `/site` or `gh-pages` branch).
- [ ] Configure custom domain (e.g., `penmunshi.tech`) and update DNS CNAME.
- [ ] Verify the hosted replay banner appears and findings load cleanly with zero backend requirement.

---

## 3. Real First-User Testing Session
- [ ] Share PenMunshi with a security peer or colleague (follow `docs/FIRST_USER.md`).
- [ ] Run a 15-minute walkthrough importing a Burp or Nmap finding.
- [ ] Collect 2–3 genuine user quotes regarding review time and fact-checking reliability.
- [ ] Replace `TODO(human)` placeholders in Section 9 of `docs/POST_DRAFT.md`.

---

## 4. Record 90-Second Demo Video
- [ ] Follow `docs/DEMO_SCRIPT.md`.
- [ ] Capture the 4 beats:
  1. Offline terminal launch (`penmunshi serve --backend ollama`).
  2. UI finding review with quote click-to-evidence solid green highlighting.
  3. Screenshot OCR auto-redaction before/after preview.
  4. Instant export to verified DOCX/HTML report.
- [ ] Upload to YouTube, Vimeo, or Loom (public/unlisted).
- [ ] Replace `TODO(human: insert demo video url)` in `README.md` and `docs/POST_DRAFT.md`.

---

## 5. DevRelay & DEV.to Publishing
- [x] Register `PenMunshi` in DevRelay (`create_project`): **ID `01a142fe-febd-36c8-249e-d08fea4a197d`**
- [x] Submit the agent session transcript to DevRelay (`submit_agent_session`): **Session ID `912`**
  - Public Session URL: [dev.to/agent_sessions/building-penmunshi-offline-first-pentest-copilot-with-local-gemma-4-besvho](https://dev.to/agent_sessions/building-penmunshi-offline-first-pentest-copilot-with-local-gemma-4-besvho)
  - Embedded Liquid Tag: `{% agent_session 912 %}`
- [x] Stage draft post on DEV (`create_article`): **Article ID `4859871`**
  - **Edit & Preview URL**: [dev.to edit draft](https://dev.to/farhans123456/penmunshi-an-offline-pentest-report-copilot-where-gemma-writes-and-code-checks-every-fact-464n-temp-slug-6700678/edit)
- [ ] Review draft on DEV, paste your final video link & `.tech` domain, and hit **Publish** before the deadline (**Oct 18, 11:59 PM PDT**).

