# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

See also [.claude/CLAUDE.md](.claude/CLAUDE.md) for the feature-oriented project overview (scan flow, module responsibilities, project_info.json schema, recent changes). This file focuses on commands and cross-file architecture.

## Commands

```bash
# First-time setup (Kali/WSL2). Installs Docker, pulls ZAP image, fetches ffuf,
# creates .venv, and rewrites run_app.sh to use it. Requires sudo.
chmod +x setup.sh && sudo ./setup.sh

# Run the app — starts ZAP container on :8080 then uvicorn on :8001 (reload=on)
./run_app.sh

# Stop app + ZAP container. Add -r / --remove to also delete the container.
./stop_app.sh [-r]
```

- Entry point: [main.py](main.py) (uvicorn with `reload=True`).
- Host/port come from [config.py](config.py) (`ARTO_HOST`, `ARTO_PORT`). Default URL: http://localhost:8001.
- `.env` at repo root is auto-loaded by both `run_app.sh` and `main.py` (via python-dotenv).
- No test suite, linter, or formatter is configured. Do not invent commands for them.
- ZAP must be reachable at `localhost:8080` with `api.disablekey=true` — this is how `run_app.sh` starts it.

## Architecture

ARTO is a single-page FastAPI app: the backend exposes routers under `/api/*` and the frontend is one SPA served from [templates/index.html](templates/index.html) plus ES6 modules under [static/js/modules/](static/js/modules/). All non-API routes fall through to the SPA (catch-all in [main.py](main.py)).

### Request → scan pipeline

A scan run is a **streamed, per-session** pipeline, not a request/response. Understanding the flow requires reading several files together:

1. **Router layer** ([api/](api/)): each file is a FastAPI router auto-registered in [main.py](main.py). Key ones:
   - `scan.py` — starts the recon+AI pipeline (SSE stream)
   - `nuclei.py` — runs Nuclei on collected endpoints (SSE stream)
   - `triage.py` — Phase 2 "Triage Gate" that routes findings to specialist agents
   - `agent.py`, `terminal.py`, `zap.py`, `nmap.py`, `precheck.py`, `history.py`, `session_ops.py`

2. **Core infra** ([core/](core/)):
   - `session.py` — session directory layout under `results/scan/{session_id}/`
   - `sse.py` — Server-Sent Events helpers used by every streaming endpoint
   - `cancellation.py` — cooperative cancel tokens; long-running scans must check these
   - `logging.py` — structured log emission fed to the frontend via SSE

3. **Agents** ([agents/](agents/)): Claude-API-backed analyzers.
   - `pentest_agent.py` + `pentest_shared.py` — main per-endpoint analyzer that emits AI cards.
   - `specialist_agent.py` / `specialists.py` — Phase 2 specialists invoked by the Triage Gate for deeper, class-specific analysis (SQLi, XSS, etc.).
   - `recon.py`, `analysis.py` — shared helpers.
   - Files prefixed with `_pentest_*` are alternate/legacy backends (Claude / Gemini / React-style) — treat as reference unless a task specifically targets them.

4. **Session state on disk** — the single source of truth between phases is the session directory. Each phase reads the previous phase's JSON and writes its own:

   ```
   results/scan/{session_id}/
     project_info.json       # settings (written by history.py)
     endpoints.json          # recon output → input to AI
     ai_findings.json        # AI analyzer output → input to triage/nuclei
     nuclei/findings.jsonl   # nuclei output (JSONL, one finding per line)
   ```

   When modifying one phase, check what the next phase expects from these files before changing their schema.

5. **Frontend** ([static/js/modules/](static/js/modules/)): vanilla ES6 modules loaded by [templates/index.html](templates/index.html). `scan.js` orchestrates the whole client-side flow and triggers `nuclei.js` when `enable_nuclei` is set. All status text goes through `appendLog(msg, source)` in `ui.js` — use it rather than writing to DOM directly so the log badge/color system stays consistent. Nuclei results live in `endpoints.js`'s `nucleiResults` global and render into a panel inside the Endpoints tab (there is no separate Nuclei tab).

### Cross-cutting conventions

- **Streaming**: every long-running endpoint returns SSE via `core/sse.py`. The frontend consumes it with `EventSource` / `fetch` + reader in the relevant module. Event types in use include `log`, `ai_card`, `scan_complete` — preserve these names when adding events.
- **Cancellation**: scans are cancellable via `core/cancellation.py`. New long loops in agents or routers must poll the cancel token.
- **Adding a router**: create `api/newthing.py` exporting `router`, then add both `from api.newthing import router as newthing_router` and `app.include_router(newthing_router)` to [main.py](main.py). The SPA catch-all makes any path not starting with `api/` return `index.html`, so non-`/api` routes won't work as JSON endpoints.
- **Adding a scan phase**: wire it into the frontend sequence in `scan.js` (after AI, before/after Nuclei) *and* persist its output as a new JSON file under the session dir so downstream phases / reloads can find it. Add an `enable_*` flag through `history.py` ↔ `settings.js` ↔ `projects.js` so it round-trips with project save/load.

### External dependencies assumed to be running

- **OWASP ZAP** at `localhost:8080` (daemon, no API key). Started by `run_app.sh`. [zap_client.py](zap_client.py) wraps it.
- **ffuf** on `$PATH` (installed by `setup.sh` into a location on PATH).
- **nuclei** on `$PATH`.
- **Claude API** key via `.env` (`ANTHROPIC_API_KEY`) — required for the AI phase; recon/Nuclei work without it.
