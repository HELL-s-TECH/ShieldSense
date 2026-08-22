# ShieldSense

An AI agent that watches your inbox and browser, scores what it finds, and explains itself in plain language — before you ever click.

**Live:** [shield-sense.vercel.app](https://shield-sense.vercel.app)

## Structure

- **`frontend/`** — the landing page / demo UI. Static HTML/CSS/JS, no build step.
- **`backend/`** — the detection pipeline. FastAPI + a rule-based classifier + a trained text model (TF-IDF/Logistic Regression, 82k labeled emails) + URL lexical features, with a RAG/LLM escalation tier for ambiguous cases.

## Running it locally

**Frontend:**
```bash
cd frontend
python3 -m http.server 8000
# open http://localhost:8000/index.html
```

**Backend:**
```bash
cd backend
python -m venv env && source env/Scripts/activate   # or env/bin/activate on macOS/Linux
pip install -r requirements.txt
uvicorn detector.api:app --port 8000
```

The frontend expects the backend at `http://127.0.0.1:8000` (see `API_BASE` in `frontend/index.html`) — update that once the backend has a real deployed URL.

### Enabling real Claude reasoning

Ambiguous cases (and invalid-input replies) work without any setup — they use a plain template. To get real Claude-written explanations instead:

```bash
cd backend
cp .env.example .env
# open .env and paste in your own ANTHROPIC_API_KEY
```

`.env` is gitignored — it never gets committed. Nothing else needs to change; `detector/reasoner.py` and `detector/validator.py` both pick it up automatically at startup.

## Status

Core pipeline (classifier, text model, URL features, decision/guardrail logic, scan history, invalid-input handling) is built and wired end to end between frontend and backend. Auth (login/sign-up) and a live inbox/browser integration (currently a mock inbox) are next.
