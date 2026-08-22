# ShieldSense

An AI agent that watches your inbox and browser, scores what it finds, and explains itself in plain language — before you ever click.

Built by **HELL'S TECH** for Industry Hack, Stage 2.

## What this is

This repo is the landing page for ShieldSense — a static, single-page pitch site. It's the frontend and design pass only; there's no backend yet, so the scan form, login/sign-up, and mock inbox all run on hardcoded example data.

## What's on the page

- **Hero** — the pitch, plus a "drop in a link, an email, or a file" scan bar
- **How it works** — the four-step detection pipeline in plain language: watch → fast filter → deep reasoning → guarded action
- **See it in action** — a status summary (dangerous / suspicious / safe counts) and a sample scanned inbox with per-item risk explanations
- **Why ShieldSense** — what makes it different from a signature-based scanner
- **Report fraud** — a direct link to 1930, India's National Cybercrime Helpline

## Running it locally

It's a single self-contained HTML file — no build step, no dependencies.

```bash
python3 -m http.server 8000
# then open http://localhost:8000/index.html
```

Or just open `index.html` directly in a browser.

## Stack

Plain HTML, CSS, and vanilla JS. Fonts via Google Fonts (Sora, IBM Plex Sans, IBM Plex Mono). No frameworks, no build tooling.

## Status

Frontend/design pass complete. Core agent functionality (the actual detection pipeline, live scanning, auth, SMS/call integrations) is the next stage of work.
