# E-Waste Guide — backend

No dependencies. Needs Python 3.9+.

    python3 server.py
    # open http://127.0.0.1:8000

Data lives in `ewaste.db` (SQLite, created on first run).

Env vars: `PORT`, `HOST`, `EWG_DB`, `COOKIE_SECURE=1` (set when serving over HTTPS).

## API (JSON, cookie session `ewg_sid`)

| Method | Path | Who | Purpose |
|---|---|---|---|
| POST | /api/auth | anyone | Log in, or register if the name is new. Body: name, role, pass (6+ chars) |
| POST | /api/logout | anyone | End session |
| GET | /api/me | anyone | Current user or null |
| GET/POST | /api/deposits | logged in | Own deposits / log one (item, qty) |
| GET/POST | /api/requests | logged in | Own pickup requests / create (item, qty, addr, date) |
| GET | /api/requests/open | kabadiwala | All requests |
| POST | /api/requests/:id/collect | kabadiwala | Mark collected |
| GET/PUT | /api/society | admin writes | Society registration |
| GET | /api/stats | anyone | Totals and per-category counts |
| POST | /api/feedback | anyone | Save feedback |
