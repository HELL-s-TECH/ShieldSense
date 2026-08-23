# ShieldSense

An AI agent that scans links, emails, and files, scores the risk (safe / suspicious / dangerous), and explains itself in plain language instead of just saying "danger" — before you ever click.

**Live:** [shield-sense.vercel.app](https://shield-sense.vercel.app) *(frontend only — see [Status](#status) below)*

## What it does

- **Scans three input types**: a pasted link, pasted email text (with an optional sender address), or a filename/attachment.
- **Three-tier detection pipeline**:
  1. Fast rule-based checks — domain lookalikes, URL lexical features (IP addresses, hyphenated typosquats, link shorteners, etc.), attachment extension checks.
  2. A trained text classifier (TF-IDF + Logistic Regression, 82k labeled emails, ~99% precision/recall) that reads the actual wording of an email for phishing language.
  3. An LLM reasoning tier (Groq, Claude, or xAI/Grok — auto-detected by key) that writes a plain-language explanation for ambiguous, low-confidence cases. Falls back to a template if no key is configured.
- **Guardrail by design**: a "dangerous" verdict is only ever *recommended* — nothing is treated as blocked until a human confirms it (Confirm block / Mark as safe).
- **Full audit trail**: every scan and every decision made on it is logged to SQLite.
- **Real accounts**: signup/login (by email or display name) with bcrypt + JWT, on their own page, landing you on a private dashboard.
- **Private dashboard**: scan composer with an auto-growing multi-line text box, a status report (dangerous/suspicious/safe counts), and scan history — all updating live as you scan.
- **Live demo mode**: the public landing page's "See it in action" section runs a simulated inbox through the real pipeline (display-only, doesn't touch the real scan history).

## Structure

```
frontend/          static site, no build step
  index.html          public landing page + live demo + scan composer
  login.html          login / signup
  dashboard.html       private workspace: composer, status report, scan history
backend/            FastAPI + detection pipeline
  detector/
    preprocess.py       raw input -> structured features
    url_features.py     URL lexical red flags
    classifier.py       rule-tier scoring (domains, URLs, attachments)
    text_model.py       trained email-text phishing classifier
    reasoner.py         LLM escalation tier (Groq / Claude / xAI)
    retriever.py        finds similar past scans for context
    validator.py        rejects gibberish input before it reaches the classifier
    decision.py         merges tiers into a verdict + guardrail
    history.py          SQLite scan history + decisions
    auth.py             accounts (separate database from scan history)
    api.py              FastAPI routes
n8n/                orchestration workflow (illustrative — see n8n/README.md)
vercel.json         rewrites / -> frontend/
```

## Running it locally

**Backend:**
```bash
cd backend
python -m venv env && source env/Scripts/activate   # or env/bin/activate on macOS/Linux
pip install -r requirements.txt
uvicorn detector.api:app --port 8000
```

**Frontend** (separate terminal — note this must be a different port than the backend):
```bash
cd frontend
python -m http.server 8600
# open http://localhost:8600/index.html
```

The frontend expects the backend at `http://127.0.0.1:8000` (see `API_BASE` in each HTML file) — update that once the backend has a real deployed URL.

### Enabling real LLM reasoning

Ambiguous cases (and invalid-input replies) work without any setup — they use a plain template. To get real LLM-written explanations instead:

```bash
cd backend
cp .env.example .env
# open .env and paste in a GROQ_API_KEY (free, no card — console.groq.com/keys),
# or an ANTHROPIC_API_KEY / XAI_API_KEY if you have one
```

`.env` is gitignored — it never gets committed. Nothing else needs to change; `detector/reasoner.py` and `detector/validator.py` both pick up whichever key is present automatically at startup.

## Status

Built and working end to end: the full detection pipeline, real accounts, the private dashboard, and the LLM reasoning tier.

Known, disclosed limitations:
- **File scanning is metadata-only** — filename/extension heuristics, not real content scanning or a sandbox.
- **No live inbox/browser integration yet** — everything is manual paste; the landing page's "See it in action" section is a simulated feed standing in for that.
- **Backend isn't deployed** — it only runs locally right now. The live Vercel frontend's scan box only works for whoever is running the backend on their own machine.
- **CORS is wide open** (`allow_origins=["*"]`) — fine for local dev/demo, would need tightening before a real deployment.
- **Scans aren't scoped per user** — every logged-in user currently sees the same shared scan history, not their own individual one.
- **n8n orchestration is illustrative** — it shows where an always-on approval gate would sit structurally; the dashboard's Confirm/Mark-safe buttons are the actual working guardrail today, not the n8n Wait node.
