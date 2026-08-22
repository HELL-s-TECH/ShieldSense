# n8n orchestration

`shieldsense-workflow.json` is the always-on orchestration layer: it polls the
mock inbox on a schedule and demonstrates where the guardrail (human approval
before any block) lives structurally in the pipeline.

## What it does

```
Schedule Trigger (every 1 min)
  -> GET /mock-inbox
  -> split the response into individual items
  -> IF requires_confirmation:
       true  -> Wait node (pauses for approval)
       false -> No-op (already logged by the /mock-inbox call itself)
```

**Important:** the `Wait` node here is structural — it shows *where* n8n
would hold a dangerous item for approval in a fuller build. The actual,
working approval mechanism right now is the **frontend's Confirm
block / Mark as safe buttons**, which call `POST /scan/{id}/decision`
directly and are fully wired end to end. Don't rely on resuming the n8n
Wait node for a live demo — use the website.

## Running it

```bash
cd n8n
npx n8n start
```

Opens the editor at `http://localhost:5678`. Import the workflow:

```bash
npx n8n import:workflow --input=shieldsense-workflow.json
```

Then open it in the editor and activate it. It calls `http://127.0.0.1:8000/mock-inbox`,
so the backend needs to be running first (`cd backend && uvicorn detector.api:app --port 8000`).

## Why this design

- **Schedule Trigger** is the "always watching" behavior — no manual scan needed for inbox items.
- **Split into items** processes each inbox item independently, so one dangerous item doesn't block evaluation of the rest.
- **IF requires_confirmation** is the guardrail check, read directly off the backend's decision — the same `action != "log_only"` logic that drives the frontend's UI.
- **Wait node** is the honest representation of "this needs a human before anything destructive happens" — n8n's Wait node genuinely pauses the workflow rather than faking a delay.
