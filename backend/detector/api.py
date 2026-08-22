"""FastAPI routes. Thin layer over decide() + history logging."""

import json
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

load_dotenv()  # picks up ANTHROPIC_API_KEY from backend/.env if present

from detector import auth
from detector.decision import decide
from detector.history import get_history, log_scan, record_user_decision, summary_counts
from detector.preprocess import preprocess
from detector.validator import assess_input, invalid_input_message

MOCK_INBOX_PATH = Path(__file__).resolve().parent.parent / "data" / "mock_inbox.json"

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
    valid: bool = True
    message: str | None = None  # set when valid=False, explaining why
    id: int | None = None
    label: str | None = None
    score: int | None = None
    confidence: str | None = None
    explanation: str | None = None
    explanation_source: str | None = None
    action: str | None = None
    requires_confirmation: bool | None = None


class DecisionRequest(BaseModel):
    decision: Literal["confirmed_block", "marked_safe"]


class SignupRequest(BaseModel):
    name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class AuthResponse(BaseModel):
    token: str
    name: str
    email: str


def get_current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not logged in.")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        return auth.current_user(token)
    except auth.AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/signup", response_model=AuthResponse)
def signup(payload: SignupRequest):
    try:
        return auth.signup(payload.name, payload.email, payload.password)
    except auth.AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    try:
        return auth.login(payload.email, payload.password)
    except auth.AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@app.get("/auth/me")
def me(current_user: dict = Depends(get_current_user)):
    return current_user


@app.post("/scan", response_model=ScanResponse)
def scan(payload: ScanRequest):
    if not any([payload.link, payload.email_text, payload.sender_email, payload.subject]):
        raise HTTPException(status_code=400, detail="Provide at least a link, email text, or sender/subject.")

    item = {
        "sender_name": payload.sender_name,
        "sender_email": payload.sender_email,
        "subject": payload.subject,
        "body": payload.email_text,
        "link": payload.link,
        "attachment": payload.attachment,
    }

    features = preprocess(item)
    rejection_reason = assess_input(features, payload.link, payload.email_text)
    if rejection_reason:
        raw_text = payload.link or payload.email_text or ""
        return ScanResponse(valid=False, message=invalid_input_message(raw_text))

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


@app.get("/mock-inbox")
def mock_inbox():
    """The simulated always-on feed: runs every seed item through the real
    pipeline and logs it as an 'auto' scan, standing in for a live
    Gmail/browser integration until that's wired up.
    """
    items = json.loads(MOCK_INBOX_PATH.read_text(encoding="utf-8"))
    results = []
    counts = {"safe": 0, "suspicious": 0, "dangerous": 0}

    for item in items:
        result = decide(item)
        scan_id = log_scan(item, result, source="auto")
        counts[result.label] += 1
        results.append(
            {
                "id": scan_id,
                "sender_name": item.get("sender_name"),
                "sender_email": item.get("sender_email"),
                "subject": item.get("subject"),
                "timestamp": item.get("timestamp"),
                "label": result.label,
                "score": result.score,
                "confidence": result.confidence,
                "explanation": result.explanation,
                "explanation_source": result.explanation_source,
                "action": result.action,
                "requires_confirmation": result.requires_confirmation,
            }
        )

    return {"items": results, "counts": counts}
