---
title: CodeSecurityAuditEnv
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
pinned: false
---

# CodeSecurityAuditEnv

## Overview

CodeSecurityAuditEnv is an OpenEnv-compatible, deterministic reinforcement learning environment for evaluating security reasoning on source code.

## Features

- Deterministic multi-step environment (`reset -> step -> state`)
- Typed FastAPI interface for local and container deployment
- Rule-based, reproducible grading and rewards
- Built-in benchmark tasks spanning easy, medium, and hard difficulty
- Supports strict and tolerant evaluation modes

## Project Structure

```text
project/
|-- app/
|   |-- main.py        # FastAPI API layer
|   |-- env.py         # Environment logic
|   |-- grader.py      # Deterministic scoring
|   |-- models.py      # Typed schemas
|   |-- tasks.py       # Task definitions
|-- inference.py       # Baseline runner (API or mock mode)
|-- openenv.yaml       # OpenEnv metadata
|-- Dockerfile
|-- requirements.txt
|-- README.md
```

## Setup Instructions

### Local

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 7860
```

### Docker

```bash
docker build -t code-security-env .
docker run --rm -p 7860:7860 code-security-env
```

## API Endpoints

- `GET /`  
  Returns service status.
- `GET /reset`  
  Starts a new episode and returns an observation.
- `POST /step`  
  Applies one action and returns `observation`, `reward`, `done`, and `info`.
- `GET /health`  
  Returns health status.

## Environment Variables

- `API_BASE_URL`  
  Base URL for OpenAI-compatible inference API.
- `MODEL_NAME`  
  Model identifier used for inference requests.
- `HF_TOKEN`  
  Hugging Face token used for authenticated API calls.
- `STRICT_MODE`  
  `0` for tolerant mode, `1` for strict mode.

Example `.env`:

```env
API_BASE_URL=https://api-inference.huggingface.co/v1
MODEL_NAME=deepseek-ai/DeepSeek-R1:fastest
HF_TOKEN=hf_your_token_here
STRICT_MODE=0
```

## Example Usage

### Reset

```bash
curl -X GET http://localhost:7860/reset
```

### Step

```bash
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "report_vulnerability",
    "vulnerability_type": "SQL Injection",
    "line": 1
  }'
```
