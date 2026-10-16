"""Local web server. Binds to 127.0.0.1 by default; nothing is persisted on disk or in the browser."""

from __future__ import annotations

import threading
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from . import __version__
from .config import Settings
from .llm import LLM, FakeLLM
from .models import Engagement, Report, VerifiedFinding
from .pipeline import EvidenceFile, FindingInput, analyze_finding, build_report, summarize
from .report import count_severities, render_docx, render_html, render_markdown
from .verify.catalog import Catalog

WEB_DIR = Path(__file__).parent / "web"
MAX_UPLOAD_BYTES = 12 * 1024 * 1024


class ExportBody(BaseModel):
    engagement: Engagement = Field(default_factory=Engagement)
    findings: list[VerifiedFinding]
    executive_summary: str = ""


class SummaryBody(BaseModel):
    findings: list[VerifiedFinding]


def create_app(llm: LLM | None = None, settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    llm = llm or FakeLLM()
    catalog = Catalog.load()
    lock = threading.Lock()  # one analysis at a time: a laptop GPU has no room for two
    app = FastAPI(title="PenMunshi", version=__version__, docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return (WEB_DIR / "index.html").read_text(encoding="utf-8")

    @app.get("/api/health")
    def health() -> dict:
        info = llm.health()
        info["version"] = __version__
        return info

    @app.post("/api/analyze")
    async def analyze(
        notes: str = Form(""),
        tool_output: str = Form(""),
        tester_vector: str = Form(""),
        tester_severity: str = Form(""),
        finding_id: str = Form("F-001"),
        files: list[UploadFile] = File(default_factory=list),
    ) -> JSONResponse:
        if not notes.strip() and not tool_output.strip() and not files:
            raise HTTPException(422, "Add notes, tool output or a screenshot first.")
        images: list[EvidenceFile] = []
        for upload in files:
            data = await upload.read()
            if len(data) > MAX_UPLOAD_BYTES:
                raise HTTPException(413, f"{upload.filename} is larger than 12 MB.")
            images.append(EvidenceFile(name=Path(upload.filename or "evidence.png").name, data=data))
        inp = FindingInput(
            id=finding_id.strip() or "F-001",
            notes=notes,
            tool_output=tool_output,
            images=images,
            tester_vector=tester_vector or None,
            tester_severity=tester_severity or None,
        )

        def work() -> VerifiedFinding:
            with lock:
                return analyze_finding(inp, llm, catalog=catalog, settings=settings)

        finding = await run_in_threadpool(work)
        return JSONResponse(finding.model_dump())

    @app.post("/api/summary")
    async def summary(body: SummaryBody) -> dict:
        def work() -> dict:
            with lock:
                text, issues = summarize(body.findings, llm)
            return {"summary": text, "lint": [i.model_dump() for i in issues]}

        return await run_in_threadpool(work)

    @app.post("/api/export")
    async def export(body: ExportBody, fmt: str = "html") -> Response:
        report = Report(
            engagement=body.engagement,
            findings=body.findings,
            executive_summary=body.executive_summary,
            severity_counts=count_severities(body.findings),
            generated_at=build_report(body.engagement, [], llm).generated_at,
            tool={"name": "PenMunshi", "version": __version__, "model": getattr(llm, "name", "")},
        )
        if fmt == "html":
            return Response(render_html(report), media_type="text/html")
        if fmt == "md":
            return Response(render_markdown(report), media_type="text/markdown")
        if fmt == "docx":
            return Response(
                render_docx(report),
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
        raise HTTPException(422, "fmt must be html, md or docx")

    return app
