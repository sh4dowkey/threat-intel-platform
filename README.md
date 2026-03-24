<div align="center">

```
████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
   ██║   ███████║██████╔╝█████╗  ███████║   ██║
   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║
   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝

██╗███╗   ██╗████████╗███████╗██╗
██║████╗  ██║╚══██╔══╝██╔════╝██║
██║██╔██╗ ██║   ██║   █████╗  ██║
██║██║╚██╗██║   ██║   ██╔══╝  ██║
██║██║ ╚████║   ██║   ███████╗███████╗
╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝
```

# Threat Intelligence Platform

**An AI-powered Security Operations Centre assistant that detects, classifies, and explains network threats in real time.**

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.0-FF6600?style=flat-square)](https://xgboost.readthedocs.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [ML Pipeline](#-ml-pipeline) · [API Reference](#-api-reference) · [Screenshots](#-screenshots) · [Roadmap](#-roadmap)

</div>

---

## Overview

The Threat Intelligence Platform (TIP) is a production-grade, open-source SOC assistant. It combines classical machine learning, modern LLMs, and real-time threat intel APIs to give security analysts an end-to-end workflow for detecting, understanding, and triaging network threats — all from a single dashboard.

**The core problem it solves:** Traditional IDS tools generate thousands of raw alerts with no context. Analysts spend 70% of their time manually researching what each alert means and what to do about it. TIP automates that entire process — it not only detects the threat but explains it in plain English, maps it to the MITRE ATT&CK framework, and tells the analyst exactly what to do next.

**Built with:**
- A two-model ML pipeline (Isolation Forest for zero-day anomalies + XGBoost for known attack classification) trained on the CICIDS2017 dataset
- SHAP explainability so every alert shows which network features triggered it
- Groq LLM (LLaMA 3) generating natural-language explanations and MITRE mappings
- Live threat intel enrichment from VirusTotal, AbuseIPDB, and AlienVault OTX
- A dark, terminal-aesthetic React dashboard built for analyst workflows

---

## ✨ Features

### 🔍 IOC Enrichment
- Submit any **IP address**, **domain name**, or **file hash** (MD5/SHA1/SHA256)
- Simultaneous enrichment from **VirusTotal** (70+ AV engines) and **AbuseIPDB**
- Composite risk score (0–100) combining signals from all sources
- Redis caching — repeated lookups are instant and don't burn API quota
- Rate limiting via sliding-window algorithm — never hits free-tier limits

### 🤖 ML Anomaly Detection
- **Isolation Forest** trained exclusively on benign traffic — detects zero-day anomalies without needing attack labels
- **XGBoost Classifier** trained on 14 attack categories from CICIDS2017 — classifies known attack types with 99%+ accuracy on DDoS/DoS/PortScan
- **SHAP feature importance** — every prediction shows the top 5 network features that drove the decision
- Combined scoring: blends both models into a single 0–100 risk score
- Supports 48 CICIDS2017 network flow features; missing features default to 0

### 🧠 LLM Alert Explanation
- Every non-clean alert gets a **Groq LLaMA 3** generated explanation including:
  - Plain-English summary of what the attack is doing
  - Technical explanation of the mechanism
  - Why specific network features triggered the alert
  - Potential impact if left unaddressed
  - Step-by-step recommended analyst action
  - False positive likelihood assessment
- **MITRE ATT&CK mapping** — automatic tactic and technique classification with direct links to attack.mitre.org
- Redis caching by alert type + risk bucket — same alert type always returns instantly after the first call

### 📊 SOC Dashboard
- Live alert feed with **auto-refresh** every 15 seconds
- **Alert timeline chart** — area chart showing malicious vs suspicious traffic over time
- **Attack class distribution** — horizontal bar chart of top attack types
- **Filterable alert queue** — filter by verdict, severity, and status
- **Full analyst workflow** — Acknowledge / Escalate / Dismiss alerts directly from the table
- **Alert detail page** — complete LLM explanation, SHAP feature bars, MITRE card, network context

### ⚡ Production-Grade Architecture
- Async FastAPI backend with SQLAlchemy async ORM
- Redis-backed sliding-window rate limiter (works across multiple async workers)
- PostgreSQL persistence via Supabase (free tier)
- Docker Compose for local development
- CI/CD via GitHub Actions
- Auto-generated OpenAPI docs at `/docs`

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        React Frontend                           │
│   Dashboard · Alerts · Alert Detail · IOC Lookup · Analyze      │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTP / REST
┌───────────────────────────▼─────────────────────────────────────┐
│                      FastAPI Backend                            │
│                                                                 │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │  /api/ioc   │  │  /api/alerts │  │      /api/ml           │  │
│  │  Enrichment │  │ CRUD + Triage│  │  Score / Status        │  │
│  └──────┬──────┘  └──────┬───────┘  └──────────┬─────────────┘  │
│         │                │                     │                │
│  ┌──────▼────────────────▼─────────────────────▼──────────────┐ │
│  │                   Service Layer                            │ │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────────────────┐  │ │
│  │  │VirusTotal  │  │  ML Service│  │    Groq LLM Service  │  │ │
│  │  │AbuseIPDB   │  │IsoForest + │  │ Alert Explanation +  │  │ │
│  │  │OTX         │  │XGBoost+SHAP│  │ MITRE ATT&CK Mapping │  │ │
│  │  └──────┬─────┘  └─────┬──────┘  └──────────┬───────────┘  │ │
│  └─────────┼──────────────┼────────────────────┼──────────────┘ │
└────────────┼──────────────┼────────────────────┼────────────────┘
             │              │                    │
    ┌────────▼──────┐  ┌────▼────────┐  ┌────────▼─────────┐
    │  Rate Limiter │  │  ML Models  │  │   Redis Cache    │
    │  (Redis SSets)│  │  .pkl files │  │  LLM + IOC + RL  │
    └────────┬──────┘  └─────────────┘  └──────────────────┘
             │
    ┌────────▼──────────────────────────────────┐
    │              PostgreSQL (Supabase)        │
    │         ioc_records · alerts tables       │
    └───────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility |
|---|---|
| `app/api/ioc.py` | IOC lookup and bulk enrichment endpoints |
| `app/api/alerts.py` | Alert analysis, listing, detail, and status updates |
| `app/api/ml.py` | ML scoring, batch scoring, model status |
| `app/services/enrichment.py` | Orchestrates VT + AbuseIPDB into a unified IOC result |
| `app/services/virustotal.py` | VirusTotal v3 API wrapper with caching |
| `app/services/abuseipdb.py` | AbuseIPDB v2 API wrapper with caching |
| `app/services/ml_service.py` | Loads trained models, runs inference, calls SHAP |
| `app/services/groq_llm.py` | Groq LLM alert explanation + MITRE mapping |
| `app/core/rate_limiter.py` | Sliding-window Redis rate limiter |
| `ml/eda.py` | CICIDS2017 dataset cleaning and preparation |
| `ml/train.py` | Model training pipeline (Isolation Forest + XGBoost + SHAP) |

---

## 🚀 Quick Start

### Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.11+ | Backend runtime |
| Node.js | 20 LTS | Frontend build |
| Docker | 25+ | Redis container |
| Git | Any | Version control |

### 1. Clone and configure

```bash
git clone https://github.com/sh4dowkey/threat-intel-platform.git
cd threat-intel-platform
```

### 2. Create API accounts (all free)

| Service | URL | What you get |
|---|---|---|
| VirusTotal | [virustotal.com](https://virustotal.com) | 500 req/day, 70+ AV engines |
| AbuseIPDB | [abuseipdb.com](https://abuseipdb.com) | 1,000 req/day, IP reputation |
| AlienVault OTX | [otx.alienvault.com](https://otx.alienvault.com) | 20M+ threat indicators |
| Groq | [console.groq.com](https://console.groq.com) | Free LLM inference (LLaMA 3) |
| Supabase | [supabase.com](https://supabase.com) | Free PostgreSQL (500MB) |

### 3. Set up the backend

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate          # Windows WSL: same command

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys and Supabase URL
```

Your `.env` file should look like:

```env
DATABASE_URL=postgresql+asyncpg://postgres:PASSWORD@db.YOURREF.supabase.co:5432/postgres
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=your-random-64-char-secret-key

VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
OTX_API_KEY=your_key_here
GROQ_API_KEY=your_key_here
GROQ_MODEL=llama3-8b-8192

MODELS_DIR=/absolute/path/to/threat-intel-platform/ml/models
ENVIRONMENT=development
```

### 4. Start Redis

```bash
docker compose -f docker/docker-compose.yml up redis -d
```

### 5. Train the ML models

```bash
cd ../ml

# Download CICIDS2017 dataset from:
# https://www.unb.ca/cic/datasets/ids-2017.html
# Request the MachineLearningCSV.zip and extract into ml/data/

python eda.py     # Clean and prepare dataset (~3 min)
python train.py   # Train models (~15–20 min)
```

> **Note:** Model files are not included in this repository (they are 7MB+). You must train them locally. The training script will save all required `.pkl` files to `ml/models/`.

### 6. Start the backend

```bash
cd ../backend
source venv/bin/activate
uvicorn app.main:app --reload
# API running at http://localhost:8000
# Interactive docs at http://localhost:8000/docs
```

### 7. Start the frontend

```bash
cd ../frontend
npm install
npm run dev
# Dashboard at http://localhost:5173
```

---

## 🧠 ML Pipeline

### Dataset

The platform is trained on **CICIDS2017** (Canadian Institute for Cybersecurity Intrusion Detection Evaluation Dataset 2017), the industry standard benchmark for IDS research.

| Property | Value |
|---|---|
| Total records | 2,830,743 flows |
| After cleaning | ~2,520,798 rows |
| Features | 78 raw → 25 SHAP-selected |
| Attack classes | 14 categories |
| Benign ratio | ~79% |
| Training subset | 200,000 rows (stratified) |

**Attack classes covered:**

| Class | MITRE Tactic | Real-World Threat |
|---|---|---|
| DDoS | Impact (TA0040) | Volumetric network flood |
| DoS Hulk / GoldenEye | Impact (TA0040) | HTTP-layer exhaustion |
| DoS slowloris / Slowhttptest | Impact (TA0040) | Connection exhaustion |
| PortScan | Reconnaissance (TA0043) | Network service discovery |
| FTP-Patator | Credential Access (TA0006) | FTP brute force |
| SSH-Patator | Credential Access (TA0006) | SSH brute force |
| Bot | Command & Control (TA0011) | C2 beacon traffic |
| Web Attack – Brute Force | Credential Access (TA0006) | Web login brute force |
| Web Attack – XSS | Execution (TA0002) | Cross-site scripting |
| Web Attack – SQL Injection | Credential Access (TA0006) | Database exploitation |
| Infiltration | Initial Access (TA0001) | Post-exploitation traffic |
| Heartbleed | Credential Access (TA0006) | OpenSSL vulnerability exploit |

### Model Architecture

```
Network Flow Features (48 raw)
           │
           ▼
    StandardScaler
           │
           ▼
    SHAP Feature Selection  ──→  Top 25 features saved to feature_columns.json
           │
    ┌──────┴──────────────────────┐
    │                             │
    ▼                             ▼
Isolation Forest            XGBoost Classifier
(unsupervised)              (supervised, 14 classes)
Trained on BENIGN           Trained on all classes
traffic only                with class balancing
    │                             │
    │  anomaly_score (0–1)        │  attack_class + confidence
    │  is_anomaly (bool)          │  top_3_classes (with proba)
    └──────────────┬──────────────┘
                   │
                   ▼
          Combined Risk Score
      (60% XGBoost + 40% IsoForest)
                   │
                   ▼
          SHAP Explanation
       (top 5 contributing features)
```

### Top SHAP-Selected Features

These 25 features were automatically selected from 48 candidates by SHAP importance on a preliminary XGBoost model:

| Rank | Feature | Importance | Why it matters |
|---|---|---|---|
| 1 | `destination_port` | 1.1665 | Port 22/23/3389 = brute force; port 0 = scan |
| 2 | `bwd_packet_length_mean` | 1.1044 | Server response size reveals attack type |
| 3 | `init_win_bytes_forward` | 1.0398 | SYN flood uses tiny window sizes |
| 4 | `fwd_packet_length_max` | 0.8399 | Large payloads indicate data exfil |
| 5 | `init_win_bytes_backward` | 0.5477 | No response = RST flood, scan |
| 6 | `psh_flag_count` | 0.4530 | HTTP vs raw TCP distinction |
| 7 | `bwd_iat_total` | 0.4405 | Server response timing patterns |
| 8 | `fwd_iat_mean` | 0.3474 | Uniform timing = automated attack |
| ... | ... | ... | ... |

### Model Performance

**XGBoost Classifier (test set, 40,000 samples):**

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| BENIGN | 1.00 | 1.00 | 1.00 | 33,253 |
| DDoS | 1.00 | 1.00 | 1.00 | 1,970 |
| PortScan | 0.99 | 1.00 | 0.99 | 1,435 |
| DoS Hulk | 1.00 | 1.00 | 1.00 | 2,781 |
| DoS GoldenEye | 0.95 | 1.00 | 0.97 | 178 |
| FTP-Patator | 0.99 | 0.99 | 0.99 | 101 |
| SSH-Patator | 1.00 | 1.00 | 1.00 | 48 |
| **Weighted avg** | **1.00** | **1.00** | **1.00** | **40,000** |

**Isolation Forest (test set):**

| Metric | Score |
|---|---|
| Precision | 0.669 |
| Recall | 0.488 |
| F1 Score | 0.564 |

> **Note on Isolation Forest metrics:** The lower F1 is expected and acceptable. Isolation Forest is an *unsupervised* model trained only on benign traffic — it has no knowledge of specific attack patterns. Its value is in detecting *novel anomalies* that XGBoost has never seen. The combined scoring architecture compensates: XGBoost handles known attacks with near-perfect accuracy, while Isolation Forest catches zero-day deviations from normal baseline.

---

## 📡 API Reference

Full interactive documentation is available at `http://localhost:8000/docs` when the server is running.

### IOC Endpoints

```
POST   /api/ioc/lookup          Enrich a single IP, domain, or hash
POST   /api/ioc/bulk            Enrich up to 10 IOCs in parallel
```

**Example — lookup a known malicious IP:**

```bash
curl -X POST http://localhost:8000/api/ioc/lookup \
  -H "Content-Type: application/json" \
  -d '{"value": "185.220.101.1"}'
```

```json
{
  "ioc": "185.220.101.1",
  "ioc_type": "ip",
  "risk_score": 74,
  "verdict": "malicious",
  "vt_malicious": 7,
  "vt_total_engines": 89,
  "abuse_confidence_score": 100,
  "abuse_total_reports": 4821,
  "abuse_isp": "Frantech Solutions",
  "sources_queried": ["virustotal", "abuseipdb"]
}
```

### Alert Endpoints

```
POST   /api/alerts/analyze      Analyze a flow: ML score + LLM explanation
GET    /api/alerts              List alerts (filterable by verdict/severity/status)
GET    /api/alerts/{id}         Get full alert with explanation
PATCH  /api/alerts/{id}         Update status: acknowledged|escalated|dismissed
```

**Example — analyze a DDoS flow:**

```bash
curl -X POST http://localhost:8000/api/alerts/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "features": {
      "flow_duration": 1000,
      "total_fwd_packets": 50000,
      "syn_flag_count": 50000,
      "ack_flag_count": 0,
      "flow_bytes_per_s": 3000000000
    },
    "source_ip": "185.220.101.1",
    "destination_port": 80
  }'
```

```json
{
  "id": 42,
  "risk_score": 91,
  "verdict": "malicious",
  "attack_class": "DDoS",
  "severity": "critical",
  "summary": "High-volume SYN flood from a known Tor exit node targeting port 80.",
  "what_is_happening": "The attacker is sending thousands of TCP SYN packets...",
  "recommended_action": "1. Block source IP at perimeter firewall immediately...",
  "mitre": {
    "tactic_id": "TA0040",
    "tactic_name": "Impact",
    "technique_id": "T1498",
    "technique_name": "Network Denial of Service",
    "technique_url": "https://attack.mitre.org/techniques/T1498/"
  },
  "top_features": [
    {"feature": "syn_flag_count", "importance": 1.1665, "value": 50000},
    {"feature": "init_win_bytes_backward", "importance": 0.5477, "value": 0}
  ]
}
```

### ML Endpoints

```
GET    /api/ml/status           Check if models are trained and loaded
GET    /api/ml/features         List the 25 expected feature names
POST   /api/ml/score            Score a single flow
POST   /api/ml/score/batch      Score up to 50 flows
```

---

## 🗂 Project Structure

```
threat-intel-platform/
│
├── backend/                        # FastAPI backend
│   ├── app/
│   │   ├── api/
│   │   │   ├── alerts.py           # Alert CRUD + analysis endpoint
│   │   │   ├── ioc.py              # IOC lookup endpoints
│   │   │   └── ml.py               # ML scoring endpoints
│   │   ├── core/
│   │   │   ├── config.py           # Pydantic settings (loads .env)
│   │   │   ├── database.py         # Async SQLAlchemy engine
│   │   │   ├── rate_limiter.py     # Sliding-window Redis rate limiter
│   │   │   └── redis.py            # Async Redis client singleton
│   │   ├── models/
│   │   │   ├── alert.py            # Alert DB table
│   │   │   └── ioc.py              # IOC record DB table
│   │   ├── services/
│   │   │   ├── abuseipdb.py        # AbuseIPDB v2 API wrapper
│   │   │   ├── enrichment.py       # IOC orchestrator (VT + AbuseIPDB)
│   │   │   ├── groq_llm.py         # Groq LLM + MITRE mapping
│   │   │   ├── ml_service.py       # Model loader + inference
│   │   │   └── virustotal.py       # VirusTotal v3 API wrapper
│   │   └── main.py                 # FastAPI app + lifespan
│   ├── tests/
│   │   ├── test_api.http           # IOC endpoint tests (REST Client)
│   │   ├── test_ml.http            # ML endpoint tests
│   │   └── test_alerts.http        # Alert endpoint tests
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/                       # React dashboard
│   ├── src/
│   │   ├── components/
│   │   │   ├── Sidebar.jsx         # Navigation + API status indicator
│   │   │   └── ui.jsx              # RiskBar, VerdictBadge, StatCard, etc.
│   │   ├── lib/
│   │   │   └── api.js              # Axios API client (all endpoints)
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx       # Live stats + charts + alert feed
│   │   │   ├── Alerts.jsx          # Filterable alert queue
│   │   │   ├── AlertDetail.jsx     # Full LLM explanation + SHAP + MITRE
│   │   │   ├── IOCLookup.jsx       # IOC enrichment UI
│   │   │   └── AnalyzeFlow.jsx     # Flow analysis with presets
│   │   ├── App.jsx                 # Router + API health check
│   │   └── index.css               # Dark terminal design system
│   └── vite.config.js
│
├── ml/                             # ML training pipeline
│   ├── eda.py                      # Dataset cleaning + EDA
│   ├── train.py                    # Model training (IsoForest + XGBoost + SHAP)
│   ├── data/                       # gitignored — place CICIDS2017 CSVs here
│   └── models/                     # gitignored — generated by train.py
│       ├── scaler.pkl
│       ├── isolation_forest.pkl
│       ├── xgboost_classifier.pkl
│       ├── feature_columns.json
│       └── label_map.json
│
├── docker/
│   ├── docker-compose.yml          # Redis + backend + Celery worker
│   └── Dockerfile
│
└── .github/
    └── workflows/
        └── ci.yml                  # GitHub Actions CI
```

---

## 🔒 Security Design

### Rate Limiting

All external API calls go through a **sliding-window rate limiter** backed by Redis sorted sets. Before every API call, the limiter:

1. Removes timestamps older than the window from a Redis sorted set
2. Counts remaining calls in the window
3. If under the limit — records the timestamp and proceeds immediately
4. If at the limit — calculates the exact wait time until the oldest slot expires and sleeps precisely that long

This guarantees rate limits are respected even with multiple concurrent async workers, without ever returning a 429 error to the frontend.

| API | Limit enforced |
|---|---|
| VirusTotal | 4 req/min (free tier hard limit) |
| AbuseIPDB | 10 req/min (conservative, daily quota protection) |
| Groq | 5 req/min (LLM token budget management) |
| AlienVault OTX | 10 req/min (polite crawling) |

### Caching Strategy

| Data type | TTL | Rationale |
|---|---|---|
| VirusTotal results | 1 hour | Reputation data doesn't change minute-to-minute |
| AbuseIPDB results | 30 minutes | Abuse reports update more frequently |
| LLM explanations | 24 hours | Same alert type always gets the same explanation |

### Secret Management

- All API keys loaded via `pydantic-settings` from `.env` — never hardcoded
- `.env` is gitignored — `.env.example` with placeholder values is committed instead
- ML model files are gitignored — regenerated locally, never travel through git

---

## 🧪 Testing

The `backend/tests/` directory contains `.http` files usable with the VS Code REST Client extension — no Postman needed.

```bash
# Run all tests via REST Client:
# Open each .http file and click "Send Request" above each endpoint
backend/tests/test_api.http       # IOC lookup tests
backend/tests/test_ml.http        # ML scoring tests
backend/tests/test_alerts.http    # Alert analysis + workflow tests
```

**Key test cases to verify the full pipeline:**

| Test | Expected outcome |
|---|---|
| Lookup `185.220.101.1` | `verdict: malicious`, `abuse_confidence_score: 100` |
| Lookup `8.8.8.8` | `verdict: clean`, low risk score |
| Score DDoS preset | `risk_score >= 70`, `attack_class: DDoS` |
| Score normal HTTP | `verdict: clean`, `risk_score < 20` |
| Analyze DDoS with source IP | Full alert with LLM explanation + MITRE T1498 |
| PATCH alert to `acknowledged` | Status updated, persisted in Supabase |

---

## 🌍 Environment Variables Reference

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | ✅ | PostgreSQL connection string (asyncpg format) |
| `REDIS_URL` | ✅ | Redis connection URL |
| `SECRET_KEY` | ✅ | 64-char random string for app security |
| `VIRUSTOTAL_API_KEY` | ✅ | From virustotal.com — free account |
| `ABUSEIPDB_API_KEY` | ✅ | From abuseipdb.com — free account |
| `OTX_API_KEY` | ⬜ | From otx.alienvault.com — optional |
| `GROQ_API_KEY` | ✅ | From console.groq.com — free, no credit card |
| `GROQ_MODEL` | ⬜ | Default: `llama3-8b-8192` |
| `MODELS_DIR` | ✅ | Absolute path to `ml/models/` directory |
| `ENVIRONMENT` | ⬜ | `development` or `production` |

---

## 🗺 Roadmap

- [ ] **WebSocket live alerts** — push new alerts to dashboard in real time without polling
- [ ] **PCAP ingestion** — upload a `.pcap` file, auto-extract flows and score them all
- [ ] **Analyst chat** — ask the LLM follow-up questions about any alert
- [ ] **Custom rule engine** — define YAML-based detection rules that feed into the alert pipeline
- [ ] **Email/Slack alerting** — push critical severity alerts to external channels
- [ ] **User authentication** — JWT-based login, role-based access (analyst / admin)
- [ ] **Multi-tenancy** — separate alert queues per organisation
- [ ] **Threat hunting** — query historical alerts by IOC, attack class, or MITRE technique
- [ ] **False positive feedback loop** — analyst dismissals retrain the model over time

---

## 📚 References & Acknowledgements

- **CICIDS2017 Dataset** — Sharafaldin, I., Habibi Lashkari, A., Ghorbani, A.A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.* ICISSP 2018.
- **MITRE ATT&CK** — MITRE Corporation. *ATT&CK for Enterprise.* [attack.mitre.org](https://attack.mitre.org)
- **XGBoost** — Chen, T., Guestrin, C. (2016). *XGBoost: A Scalable Tree Boosting System.* KDD 2016.
- **SHAP** — Lundberg, S., Lee, S.I. (2017). *A Unified Approach to Interpreting Model Predictions.* NeurIPS 2017.
- **Isolation Forest** — Liu, F.T., Ting, K.M., Zhou, Z.H. (2008). *Isolation Forest.* ICDM 2008.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built as a Final Year Project in Cybersecurity · 2025–2026

*If this project helped you, consider giving it a ⭐*

</div>