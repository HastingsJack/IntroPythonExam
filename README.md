# pyintro — E Corp Threat Hub

A CVE/KEV dashboard built for an Intro to Python course. A FastAPI backend pulls
vulnerability data from NIST NVD and CISA KEV, and a Streamlit frontend renders
metrics, charts, and a CWE→Vendor network graph. Includes a password
crack-time estimator with Have I Been Pwned (HIBP) lookup and a Mistral-backed
chat page ("Ask Elliot").

## Features

- **CVE summary** — totals, criticals, average CVSS, KEV ratio, severity pie,
  weekday-stacked bars, CVSS histogram (NVD, last N days).
- **KEV summary** — top vendor, most common CWE, ransomware campaigns,
  CWE→Vendor network graph, CWE bar chart, ransomware bubble chart (CISA KEV).
- **Watch List** — look up specific CVEs and accumulate them in a session table.
- **Password Crack Time Estimator** — entropy-based crack-time estimate plus
  HIBP k-anonymity check; plays a hidden uh-oh / woo-hoo chime on hit/miss.
- **Ask Elliot** — chat page that proxies to the Mistral API.

## Architecture

```
┌──────────────┐      HTTP       ┌──────────────┐      HTTP      ┌─────────────┐
│   Streamlit  │ ──────────────▶ │   FastAPI    │ ─────────────▶ │  NVD / KEV  │
│   frontend   │  /cves/summary  │   backend    │                │  HIBP / ... │
│  (port 8501) │  /kevs/summary  │  (port 8000) │                └─────────────┘
└──────────────┘  /password/...  └──────────────┘
                  /watchlist
```

Backend caches NVD CVEs and CISA KEVs in-process to limit upstream calls.

## Requirements

- Python 3.14+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- Docker + Docker Compose (optional)
- Mistral API key (only for the Ask Elliot page)

## Setup

### Docker Compose (recommended)

```bash
cp .env.example .env   # if you have one; otherwise create .env
docker compose up --build
```

Then open:
- Frontend: http://localhost:8501
- Backend docs: http://localhost:8000/docs

### Local development

```bash
uv sync
uv run uvicorn backend.main:app --reload --port 8000
# in a second terminal
uv run streamlit run src/frontend/Home.py
```

The frontend reads `API_URL` from the environment and falls back to
`http://localhost:8000`.

## Environment

Create a `.env` at the repo root:

```
MISTRAL_API_KEY=...   # required only for Ask Elliot
API_URL=http://localhost:8000   # frontend → backend (compose sets this)
```

## Tests

```bash
uv run pytest
```

Covers `cve_api`, `kev_api`, and `data_processing`.

## Project structure

```
src/
├── backend/
│   ├── main.py                 FastAPI app and routes
│   ├── data_processing.py      pandas transforms over CVE/KEV data
│   ├── password_processing.py  entropy, crack-time, HIBP k-anonymity
│   └── api/
│       ├── cve_api.py          NVD client with TTL cache
│       └── kev_api.py          CISA KEV client with TTL cache
└── frontend/
    ├── Home.py                 CVE/KEV dashboard
    ├── assets/                 audio assets
    └── pages/
        ├── 1_Password.py       crack-time estimator + HIBP
        ├── 2_WatchList.py      per-CVE lookup table
        └── AskElliot.py        Mistral chat
tests/                          pytest suites
```

## API endpoints

| Method | Path                | Query           | Description                          |
|--------|---------------------|-----------------|--------------------------------------|
| GET    | `/cves/summary`     | `days` (1–30)   | CVE metrics, severity/weekday counts |
| GET    | `/kevs/summary`     | `days` (1–30)   | KEV metrics + CWE→Vendor graph       |
| GET    | `/password/cracking`| `password`      | Append + return crack-time table     |
| GET    | `/watchlist`        | `cve`           | CVE detail row                       |

## Data sources

- [NVD CVE 2.0 API](https://services.nvd.nist.gov/rest/json/cves/2.0)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Have I Been Pwned — Pwned Passwords](https://haveibeenpwned.com/Passwords) (k-anonymity)
- Sound effects from [Freesound](https://freesound.org/) (community uploads)
