# S.E.N.T.R.Y

**S**ecurity **E**vent & **N**etwork **T**hreat **R**esponse, for **Y**our cloud

A cloud SOC/SIEM platform for AWS: misconfiguration scanning, CIS compliance mapping, IaC (Terraform) scanning, ML-based anomaly detection on CloudTrail logs, threat intelligence enrichment, and a live risk dashboard.

## Status
🚧 Day 1 — environment setup in progress.

## Architecture
_(diagram coming — Week 4)_

## Features
- [ ] IAM misconfiguration scanner
- [ ] S3 misconfiguration scanner
- [ ] Security Group / network scanner
- [ ] RDS + Lambda scanner
- [ ] CIS AWS Foundations Benchmark mapping
- [ ] Terraform IaC static scanner
- [ ] CloudTrail log ingestion
- [ ] ML-based anomaly detection (Isolation Forest + ensemble)
- [ ] Sequence-based attack chain detection
- [ ] Threat intel enrichment (AbuseIPDB, VirusTotal)
- [ ] Unified risk correlation engine
- [ ] Real-time Slack/email alerting
- [ ] Historical trend tracking
- [ ] Streamlit dashboard
- [ ] PDF report generation
- [ ] Docker containerization
- [ ] CI/CD (GitHub Actions)

## Tech stack
Python · boto3 · scikit-learn · Streamlit · Plotly · SQLite · Docker · GitHub Actions

## Setup
```bash
python -m venv venv
source venv/bin/activate      # or venv\Scripts\activate on Windows
pip install -r requirements.txt
cp config/config.example.env config/.env   # then fill in your keys
```

## Legal / safety note
This tool is designed to scan **only AWS accounts you own or control**. Do not point it at infrastructure you don't have explicit authorization to test.

## What I'd add next
_(fill in at the end — shows growth mindset to recruiters)_
