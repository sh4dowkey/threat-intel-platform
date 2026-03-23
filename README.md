# Threat Intelligence Platform

AI-powered SOC assistant — IOC enrichment, ML anomaly detection, and LLM-generated alert explanations.

## Stack
- **Backend**: FastAPI, SQLAlchemy, Celery, Redis
- **ML**: Scikit-learn (Isolation Forest), XGBoost, SHAP
- **LLM**: Groq (LLaMA 3) for alert explanations + MITRE ATT&CK mapping
- **Database**: PostgreSQL (Supabase)
- **Threat Intel**: VirusTotal, AbuseIPDB, AlienVault OTX

## Setup
\`\`\`bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in your API keys
docker compose -f docker/docker-compose.yml up redis -d
uvicorn app.main:app --reload
\`\`\`

## ML Training
\`\`\`bash
cd ml
python eda.py     # clean CICIDS2017 dataset
python train.py   # train Isolation Forest + XGBoost
\`\`\`

## API Docs
Visit http://localhost:8000/docs for interactive Swagger UI.
