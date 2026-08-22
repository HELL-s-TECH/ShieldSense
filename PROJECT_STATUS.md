# ShieldSense — Project Status

_Last updated: 2026-08-23. Written for picking this up in a fresh session._

## Repo structure

```
landing-page/          <- git root, pushed to github.com/HELL-s-TECH/ShieldSense
  frontend/             static site (index.html, no build step)
  backend/              FastAPI + detection pipeline
  n8n/                  orchestration workflow (in progress)
  vercel.json           rewrites / -> frontend/ (frontend deployed on Vercel)
  README.md
```

## What's built and verified working

**Detection pipeline** (`backend/detector/`)
- `preprocess.py` — turns a raw item (link/email/file) into features
- `classifier.py` — rule tier: domain-lookalike (fuzzy match vs known brands), URL lexical features (`url_features.py`), attachment extension checks, plus a trained text model
- `text_model.py` + `train_text_model.py` — TF-IDF + Logistic Regression trained on 82,486 labeled emails (Kaggle `naserabdullahalam/phishing-email-dataset`). 99% precision/recall on held-out test. Saved to `data/models/*.joblib`, committed to repo (~1.2MB).
- `retriever.py` — finds similar past cases via text similarity (no embedding API needed)
- `reasoner.py` — LLM escalation tier for low-confidence cases. **Auto-detects provider by key prefix** (`sk-ant-` → Claude via `anthropic` package, `xai-` → Grok via `openai` package pointed at `https://api.x.ai/v1`), checking both `ANTHROPIC_API_KEY` and `XAI_API_KEY` env vars. Falls back to a template if no key or the call fails — logs why to `data/reasoner_debug.log`.
- `validator.py` — rejects gibberish input (e.g. "rtoortn") before it reaches the classifier, with an LLM-or-template rejection message
- `decision.py` — merges everything, applies the guardrail (`dangerous` → `recommend_block`, requires frontend confirmation before anything "happens")
- `history.py` — SQLite scan log, every scan + user decision persisted
- `auth.py` — bcrypt + JWT email/password auth, real accounts
- `api.py` — FastAPI app: `/scan`, `/scan/{id}/decision`, `/history`, `/mock-inbox`, `/auth/signup`, `/auth/login`, `/auth/me`, `/health`

**Tests:** `backend/tests/test_classifier.py` — 8/8 seed cases pass. Run via `python tests/test_classifier.py` from `backend/` with venv active.

**Frontend** (`frontend/index.html`, single file, no framework)
- Hero with a scan composer (link/email/file) that calls `/scan` live
- "See it in action" section loads `/mock-inbox` live (falls back to 5 cached examples if backend unreachable)
- Confirm-block/Mark-as-safe buttons call `/scan/{id}/decision`, persist to history
- Login/Sign up modal, fully wired to `/auth/*`, session in localStorage + `/auth/me` verification on load
- `API_BASE` constant hardcoded to `http://127.0.0.1:8000` — **needs updating once backend is deployed somewhere**

## Known gaps / honest limitations (by design, not oversights)

- **File malware scanning** — extension/filename heuristics only. No AV engine, no sandbox, no content analysis. Disclosed to user explicitly.
- **No live Gmail/browser integration** — manual paste only. Frontend has a hint explaining this.
- **Backend not deployed** — only runs locally. The live Vercel frontend's scan box won't work for anyone but the developer until this is deployed (Render/Railway/Fly — not chosen yet).
- **CORS wide open** (`allow_origins=["*"]`) — fine for local dev, tighten before real deployment.
- **Reasoning tier has no working LLM key yet** — user has tried both Anthropic (zero credit balance) and xAI (invalid key so far). Runs on template fallback, which is a legitimate, honest MVP state — not broken, just not upgraded yet.

## Environment gotchas hit this session (so you don't re-debug them)

1. **This whole project lives inside OneDrive** (`C:\Users\nello\OneDrive\Desktop\hack\...`). OneDrive's real-time sync has repeatedly interfered with dotfiles and fast-writing processes:
   - `.env` / `.env.example` vanished from disk twice (file existed in git, gone from working tree) — just `git restore` them
   - n8n's first-run startup was extremely slow inside OneDrive (SQLite migrations + sync events) — fixed by pointing `N8N_USER_FOLDER` **outside** OneDrive (e.g. a temp dir)
   - If any new persistent-write tool (databases, caches) acts weirdly slow or files disappear, suspect OneDrive first
2. **Python version matters on this machine** — `py` launcher defaults to **3.14**, which has no prebuilt `pydantic-core` wheel on Windows yet (tries to compile via Rust/maturin, fails without MSVC Build Tools). Always create the venv with `py -3.11 -m venv env` explicitly, not bare `py -m venv env`.
3. **PowerShell env vars are per-window/per-tab** — `$env:X = "..."` set in one terminal tab is invisible to a server started in a different tab, even in the "same window" if using Windows Terminal tabs. Chain them on one line (`$env:X = "..."; uvicorn ...`) if setting and launching together.
4. **JWT `sub` claim must be a string** — PyJWT's newer versions enforce this per spec; an int there makes every token fail verification immediately. Already fixed (`str(user_id)` in `auth.py`), just noting it in case similar token code gets added elsewhere.

## In progress right now

**n8n orchestration** (`n8n/shieldsense-workflow.json`, `n8n/README.md` already written) — workflow JSON is built: Schedule Trigger → `GET /mock-inbox` → split items → `IF requires_confirmation` → Wait node (structural, represents the approval gate) / No-op. **Decision made:** the n8n Wait node is structural/illustrative only — the frontend's Confirm/Dismiss buttons remain the actual working guardrail mechanism for any live demo, not the n8n webhook resume. Still need to: get n8n running (was mid-restart with `N8N_USER_FOLDER` outside OneDrive when this summary was written), import the workflow, and verify at least one execution actually reaches the backend successfully. Not yet committed to git.

## Next steps (in likely priority order)

1. Finish n8n: confirm it starts, import `shieldsense-workflow.json`, verify one execution, commit
2. Sort out a working LLM key (Anthropic needs billing added, or find a valid xAI key) — optional, app works fine without it
3. Deploy the backend somewhere reachable (Render/Railway/Fly) and update `API_BASE` in `frontend/index.html`
4. Tighten CORS once the real frontend origin is known
5. Consider whether scans should be tied to logged-in users (currently auth and scanning are independent systems)

## Quick-start commands

```powershell
# Backend
cd landing-page\backend
env\Scripts\activate
uvicorn detector.api:app --port 8000 --reload

# Frontend (separate terminal)
cd landing-page\frontend
python -m http.server 8600
# open http://localhost:8600/index.html

# n8n (separate terminal, once working)
cd landing-page\n8n
npx n8n start
# opens http://localhost:5678
```
