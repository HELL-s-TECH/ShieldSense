"""FastAPI routes. Thin layer over decide() + history logging."""

from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from detector.decision import decide
from detector.history import get_history, log_scan, record_user_decision, summary_counts

app = FastAPI(title="ShieldSense API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to the real frontend origin before shipping
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    source: Literal["manual", "auto"] = "manual"
    link: str | None = None
    email_text: str | None = None
    sender_name: str | None = None
    sender_email: str | None = None
    subject: str | None = None
    attachment: str | None = None


class ScanResponse(BaseModel):
    id: int
    label: str
    score: int
    confidence: str
    explanation: str
    explanation_source: str
    action: str
    requires_confirmation: bool


class DecisionRequest(BaseModel):
    decision: Literal["confirmed_block", "marked_safe"]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
def scan(payload: ScanRequest):
    if not any([payload.link, payload.email_text, payload.sender_email, payload.subject]):
        raise HTTPException(status_code=400, detail="Provide at least a link, email text, or sender/subject.")

    item = {
        "sender_name": payload.sender_name,
        "sender_email": payload.sender_email,
        "subject": payload.subject or (payload.link and "Manual link scan") or "Manual scan",
        "body": payload.email_text,
        "link": payload.link,
        "attachment": payload.attachment,
    }

    result = decide(item)
    scan_id = log_scan(item, result, source=payload.source)

    return ScanResponse(id=scan_id, **{k: v for k, v in result.__dict__.items()})


@app.post("/scan/{scan_id}/decision")
def submit_decision(scan_id: int, payload: DecisionRequest):
    record_user_decision(scan_id, payload.decision)
    return {"ok": True}


@app.get("/history")
def history(limit: int = 50):
    return {"scans": get_history(limit), "counts": summary_counts()}
