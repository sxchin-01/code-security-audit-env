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

## 📘 Overview

CodeSecurityAuditEnv is a deterministic RL-style benchmark for code security auditing. It evaluates how an agent identifies vulnerabilities in source code, explains risk, and proposes remediation through iterative environment interaction.

The system is implemented as a FastAPI service with typed request/response models. A task is loaded on reset, actions are submitted step-by-step, and each step is scored with deterministic grading logic. This design makes results reproducible across local and containerized runs.

In addition to API interaction, the project includes a baseline runner (`inference.py`) that executes end-to-end evaluation across the full task set. It supports both deterministic mock mode and API-backed inference mode through environment variables.

This repository is suitable for benchmarking and integration testing where stable behavior and clear API contracts are required.

---

## ✅ Key Features

- Deterministic multi-step environment lifecycle (`reset -> step -> state`)
- FastAPI API layer with typed schema validation
- Reproducible scoring behavior (no randomness in grading)
- Task coverage across easy, medium, and hard vulnerabilities
- Strict mode toggle for tighter evaluation thresholds
- Docker-ready deployment for local and hosted execution

---

## 🏗️ System Architecture

High-level component flow:

1. `API Layer` (`app/main.py`) receives agent requests.
2. `Environment` (`app/env.py`) manages task state, progression, and termination.
3. `Grader` (`app/grader.py`) computes deterministic reward and score breakdown.
4. `Task Store` (`app/tasks.py`) provides canonical vulnerability scenarios.
5. `Models` (`app/models.py`) enforce schema consistency across actions and observations.

At runtime, `/reset` initializes an episode and `/step` applies one action, returning `observation`, `reward`, `done`, and `info` for the next decision.

---

## 📁 Project Structure

```text
project/
|-- app/
|   |-- main.py        # FastAPI API routes
|   |-- env.py         # Environment state and transition logic
|   |-- grader.py      # Deterministic reward/scoring logic
|   |-- models.py      # Typed request/response and domain models
|   |-- tasks.py       # Security benchmark task definitions
|-- inference.py       # Baseline evaluator (mock or API-backed)
|-- openenv.yaml       # OpenEnv-compatible metadata
|-- Dockerfile         # Container image definition
|-- requirements.txt   # Python dependencies
|-- README.md
```

---

## 🔄 How It Works

1. Start the API server.
2. Call `GET /reset` to load the next deterministic task and receive initial observation.
3. Submit an action via `POST /step`.
4. Environment validates and applies the action.
5. Grader returns deterministic reward and metadata.
6. Repeat `POST /step` until `done=true`.

This loop enables controlled benchmarking of multi-step security reasoning.

---

## ⚙️ Setup Instructions

### Local Setup

1. Create and activate a virtual environment.
2. Install dependencies.
3. Run the API server.

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 7860
```

### Docker Setup

1. Build the image.
2. Run the container.

```bash
docker build -t code-security-env .
docker run --rm -p 7860:7860 code-security-env
```

---

## 🔌 API Reference

### Endpoint Summary

| Method | Path | Description |
| --- | --- | --- |
| GET | `/` | Service status check |
| GET | `/reset` | Starts new episode and returns observation |
| POST | `/step` | Applies one action and returns transition result |
| GET | `/health` | Health check endpoint |

### `GET /`

- Description: Returns service status.
- Example request:

```bash
curl -X GET http://localhost:7860/
```

- Example response:

```json
{"status":"ok"}
```

### `GET /reset`

- Description: Starts a new episode and returns the initial observation.
- Example request:

```bash
curl -X GET http://localhost:7860/reset
```

- Example response (simplified):

```json
{
  "observation": {
    "task_id": "easy_sql_injection_01",
    "difficulty": "easy",
    "code": "...",
    "language": "python",
    "context": "...",
    "history": []
  }
}
```

### `POST /step`

- Description: Applies an action and returns transition data.
- Example request:

```bash
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "report_vulnerability",
    "vulnerability_type": "SQL Injection",
    "line": 1
  }'
```

- Example response (simplified):

```json
{
  "observation": {"task_id": "easy_sql_injection_01", "...": "..."},
  "reward": 0.72,
  "done": false,
  "info": {"done_reason": "action_graded", "...": "..."}
}
```

### `GET /health`

- Description: Returns health status.
- Example request:

```bash
curl -X GET http://localhost:7860/health
```

- Example response:

```json
{"status":"ok"}
```

---

## 🌐 Environment Variables

| Variable | Description |
| --- | --- |
| `API_BASE_URL` | Base URL for OpenAI-compatible inference API. |
| `MODEL_NAME` | Model identifier used for inference requests. |
| `HF_TOKEN` | Hugging Face token for authenticated API calls. |
| `STRICT_MODE` | `0` for tolerant mode, `1` for strict mode. |

Example:

```env
API_BASE_URL=https://api-inference.huggingface.co/v1
MODEL_NAME=deepseek-ai/DeepSeek-R1:fastest
HF_TOKEN=hf_your_token_here
STRICT_MODE=0
```

---

## 🧪 Example Usage

### Reset an episode

```bash
curl -X GET http://localhost:7860/reset
```

### Submit one step action

```bash
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "report_vulnerability",
    "vulnerability_type": "SQL Injection",
    "line": 1
  }'
```

---

## 📈 Evaluation / Scoring

- Rewards are generated deterministically by rule-based grading.
- Step output includes a detailed `info.score_breakdown` structure.
- Episode-level evaluation can be summarized with `final_score` in baseline runs.
- `STRICT_MODE` controls stricter evaluation behavior for more conservative scoring.

---

## ✅ Conclusion

CodeSecurityAuditEnv provides a deterministic, API-first benchmark for evaluating multi-step security reasoning over code.

With typed interfaces, reproducible scoring, and container-ready deployment, it can be used consistently across local testing, automated evaluation workflows, and hosted runtime environments.
