# ShieldSense — Project Status

_Last updated: 2026-08-23. Written for picking this up in a fresh session._

## Repo structure

```
landing-page/          <- git root, pushed to github.com/HELL-s-TECH/ShieldSense
  frontend/             static site, no build step
    index.html            public landing page + live demo + scan composer
    login.html            login / signup (email or name)
    dashboard.html         private workspace: composer, status report, scan history
  backend/              FastAPI + detection pipeline
  n8n/                  orchestration workflow (illustrative, see n8n/README.md)
  vercel.json           rewrites / -> frontend/ (frontend deployed on Vercel)
  README.md
```

## What's built and verified working

**Detection pipeline** (`backend/detector/`)
- `preprocess.py` — turns a raw item (link/email/file) into features
- `classifier.py` — rule tier: domain-lookalike (fuzzy match vs known brands), URL lexical features (`url_features.py`), attachment extension checks, plus a trained text model
- `text_model.py` + `train_text_model.py` — TF-IDF + Logistic Regression trained on 82,486 labeled emails (Kaggle `naserabdullahalam/phishing-email-dataset`). 99% precision/recall on held-out test. Saved to `data/models/*.joblib`, committed to repo (~1.2MB).
- `retriever.py` — finds similar past cases via text similarity (no embedding API needed)
- `reasoner.py` — LLM escalation tier for low-confidence cases. **Auto-detects provider by key prefix** (`gsk_` → Groq, `sk-ant-` → Claude, `xai-` → Grok), checking `GROQ_API_KEY`, `ANTHROPIC_API_KEY`, and `XAI_API_KEY` env vars. Groq uses `openai/gpt-oss-120b` at `max_tokens=400` (it's a reasoning model — a lower cap returns empty content). Falls back to a template if no key or the call fails — logs why to `data/reasoner_debug.log`. **Groq is confirmed working** with a real free-tier key as of this session.
- `validator.py` — rejects gibberish input (e.g. "rtoortn") before it reaches the classifier, with an LLM-or-template rejection message
- `decision.py` — merges everything, applies the guardrail (`dangerous` → `recommend_block`, requires frontend confirmation before anything "happens")
- `history.py` — SQLite scan log (`data/scan_history.db`), every scan + user decision persisted
- `auth.py` — bcrypt + JWT email/password auth, **its own database** (`data/users.db`) — deliberately separate from scan history so clearing demo scan data never wipes accounts (this caused a real bug earlier in the session; now fixed)
- `api.py` — FastAPI app: `/scan`, `/scan/{id}/decision`, `/history`, `/mock-inbox`, `/auth/signup`, `/auth/login`, `/auth/me`, `/health`

**Tests:** `backend/tests/test_classifier.py` — 8/8 seed cases pass. Run via `python tests/test_classifier.py` from `backend/` with venv active.

**Frontend**
- `index.html` — hero with a scan composer (link/email/file, multi-line textarea, Enter to scan / Shift+Enter for newline) that calls `/scan` live; "See it in action" section loads `/mock-inbox` for display only (doesn't touch the real scan history); animated shield/eye logo with a jump-cut glitch effect on the headline; Login/Sign up now link to `login.html` instead of an inline modal.
- `login.html` — standalone login/signup page, login accepts either email or display name, redirects to `dashboard.html` on success.
- `dashboard.html` — private workspace: composer (with an optional sender-email field, for testing domain-reputation signals) + a side instructions panel, a status report (dangerous/suspicious/safe counts), and scan history styled to match the landing page's mock-inbox rows (tinted by verdict). Everything re-fetches after each scan/decision so it updates live. Logging out returns to `index.html`.
- `API_BASE` constant hardcoded to `http://127.0.0.1:8000` in every HTML file — **needs updating once backend is deployed somewhere**.

## Known gaps / honest limitations (by design, not oversights)

- **File malware scanning** — extension/filename heuristics only. No AV engine, no sandbox, no content analysis. Disclosed to user explicitly.
- **No live Gmail/browser integration** — manual paste only. Frontend has a hint explaining this.
- **Backend not deployed** — only runs locally. The live Vercel frontend's scan box won't work for anyone but the developer until this is deployed (Render/Railway/Fly — not chosen yet).
- **CORS wide open** (`allow_origins=["*"]`) — fine for local dev, tighten before real deployment.
- **Scans aren't scoped per user** — every logged-in user sees the same shared scan history. Auth and scanning are still two independent systems.
- **n8n orchestration is illustrative** — the Wait node shows where an approval gate would sit; the dashboard's Confirm/Mark-safe buttons are the actual working guardrail.

## Environment gotchas hit this session (so you don't re-debug them)

1. **This whole project lives inside OneDrive** (`C:\Users\nello\OneDrive\Desktop\hack\...`). OneDrive's real-time sync has repeatedly interfered with dotfiles and fast-writing processes:
   - `.env` / `.env.example` vanished from disk twice (file existed in git, gone from working tree) — just `git restore` them
   - n8n's first-run startup was extremely slow inside OneDrive (SQLite migrations + sync events) — fixed by pointing `N8N_USER_FOLDER` **outside** OneDrive (e.g. a temp dir)
   - If any new persistent-write tool (databases, caches) acts weirdly slow or files disappear, suspect OneDrive first
2. **Python version matters on this machine** — `py` launcher defaults to **3.14**, which has no prebuilt `pydantic-core` wheel on Windows yet (tries to compile via Rust/maturin, fails without MSVC Build Tools). Always create the venv with `py -3.11 -m venv env` explicitly, not bare `py -m venv env`.
3. **PowerShell env vars are per-window/per-tab** — `$env:X = "..."` set in one terminal tab is invisible to a server started in a different tab, even in the "same window" if using Windows Terminal tabs. Chain them on one line (`$env:X = "..."; uvicorn ...`) if setting and launching together.
4. **JWT `sub` claim must be a string** — PyJWT's newer versions enforce this per spec; an int there makes every token fail verification immediately. Already fixed (`str(user_id)` in `auth.py`).
5. **Orphaned backend/frontend processes accumulate across restarts** — killing a process by re-running the start command isn't enough; on Windows, a prior `uvicorn`/`http.server` process can keep holding its port (or a stale sibling can linger) even after what looks like a clean restart, and two processes can end up answering the same port inconsistently. This caused a real signup/login bug (one process serving stale code, its sibling serving new code, requests landing on whichever). Before debugging "weird" backend behavior, check `netstat -ano | findstr :8000` (or `:8600`) for more than one listener, and kill by PID (`taskkill //F //PID <pid>`) rather than assuming a restart actually replaced the old process.
6. **`auth.py` and `history.py` must never share a database file** — they briefly did (`scan_history.db`), so clearing demo scan data during development also silently wiped every signed-up account. Now split into `users.db` and `scan_history.db`. Don't reunify them without a good reason.
7. **Groq's model catalog changes** — `llama-3.3-70b-versatile` doesn't exist on it anymore; check `GET https://api.groq.com/openai/v1/models` with the actual key before assuming a model name is valid. Currently using `openai/gpt-oss-120b`.

## Next steps (in likely priority order)

1. Get n8n's own server actually running reliably (it's been flaky/silent in terminal) — import the workflow, verify one execution reaches the backend
2. Deploy the backend somewhere reachable (Render/Railway/Fly) and update `API_BASE` in all three frontend HTML files
3. Tighten CORS once the real frontend origin is known
4. Decide whether scans should be tied to logged-in users (currently independent systems) — would need per-user filtering in `history.py`

## Quick-start commands

```powershell
# Backend
cd landing-page\backend
env\Scripts\activate
uvicorn detector.api:app --port 8000

# Frontend (separate terminal)
cd landing-page\frontend
python -m http.server 8600
# open http://localhost:8600/index.html

# n8n (separate terminal, once working)
cd landing-page\n8n
npx n8n start
# opens http://localhost:5678
```
