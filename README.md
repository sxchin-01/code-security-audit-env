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

**CodeSecurityAuditEnv** is an **OpenEnv-compatible RL environment** for deterministic security-auditing evaluation over source code.

It solves a practical problem: measuring whether an agent can **consistently detect vulnerabilities, explain risk, and propose actionable fixes** with reproducible scoring and API-driven workflows.

## 🧭 Quick Navigation

- [Overview](#-overview)
- [Why This Matters](#-why-this-matters)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [RL Loop](#-rl-loop)
- [Task Design](#-task-design)
- [API Endpoints](#-api-endpoints)
- [Environment Variables](#-environment-variables)
- [Example Usage](#-example-usage)
- [Evaluation / Results](#-evaluation--results)
- [Deployment](#-deployment)
- [OpenEnv Compliance](#-openenv-compliance)
- [Setup Instructions](#-setup-instructions)
- [Conclusion](#-conclusion)

---

## 📘 Overview

CodeSecurityAuditEnv is a deterministic RL-style benchmark for code security auditing. It evaluates how an agent identifies vulnerabilities in source code, explains risk, and proposes remediation through iterative environment interaction.

The system is implemented as a FastAPI service with typed request/response models. A task is loaded on reset, actions are submitted step-by-step, and each step is scored with deterministic grading logic. This design makes results reproducible across local and containerized runs.

In addition to API interaction, the project includes a baseline runner (`inference.py`) that executes end-to-end evaluation across the full task set. It supports both deterministic mock mode and API-backed inference mode through environment variables.

This repository is suitable for benchmarking and integration testing where stable behavior and clear API contracts are required.

---

## 🎯 Why This Matters

- **Secure code auditing is high impact**: modern software stacks rely on fast review cycles where missed vulnerabilities can propagate quickly.
- **LLM evaluation needs rigor**: one-shot demos are insufficient for security; iterative, stateful evaluation reveals real reasoning quality.
- **Reproducibility is essential**: deterministic tasks and scoring allow fair comparisons between models, prompts, and agent policies.

---

## ✅ Key Features

- **Deterministic multi-step environment lifecycle** (`reset -> step -> state`)
- **FastAPI API layer** with typed schema validation
- **Reproducible scoring behavior** (no randomness in grading)
- **Task coverage** across easy, medium, and hard vulnerabilities
- **Strict mode toggle** for tighter evaluation thresholds
- **Docker-ready deployment** for local and hosted execution
- **OpenEnv-compatible metadata** via `openenv.yaml`

---

## 🏗️ Architecture

### High-level Components

1. **API Layer** (`app/main.py`) receives agent requests.
2. **Environment** (`app/env.py`) manages task state, progression, and termination.
3. **Grader** (`app/grader.py`) computes deterministic reward and score breakdown.
4. **Task Store** (`app/tasks.py`) provides canonical vulnerability scenarios.
5. **Models** (`app/models.py`) enforce schema consistency across actions and observations.
6. **Inference Runner** (`inference.py`) executes full benchmark runs in mock or API mode.

At runtime, `/reset` initializes an episode and `/step` applies one action, returning `observation`, `reward`, `done`, and `info` for the next decision.

### Architecture Diagram

![Architecture](./assets/architecture.png)

_If `assets/architecture.png` is not present, add a project-specific architecture image at this path._

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

## 🔄 RL Loop

The interaction cycle is intentionally simple and deterministic:

1. **`reset` -> observation**
   - Client calls `/reset`.
   - Environment loads the next deterministic task and returns an initial observation.
2. **`step(action)` -> transition**
   - Client submits an action to `/step`.
   - Environment validates and applies action semantics.
3. **deterministic grading**
   - Grader computes reward and detailed score breakdown.
   - Response returns `observation`, `reward`, `done`, and `info`.

Repeat step actions until `done=true`.

### RL Flow Diagram

![RL Loop](./assets/rl-loop.png)

_If `assets/rl-loop.png` is not present, add a project-specific RL flow image at this path._

---

## 🧩 Task Design

- Tasks represent realistic security review scenarios over code snippets.
- Difficulty spans **easy**, **medium**, and **hard**.
- Ground truth vulnerabilities are defined in a canonical, deterministic task store.
- The environment advances deterministically across tasks for reproducible benchmarks.
- Output history captures previous actions to support iterative reasoning evaluation.

---

## 🔌 API Endpoints

### Endpoint Summary

| Method | Path | Description |
| --- | --- | --- |
| GET | `/` | Service status check |
| GET | `/reset` | Starts new episode and returns observation |
| POST | `/step` | Applies one action and returns transition result |
| GET | `/health` | Health check endpoint |

All API requests and responses use JSON. For `POST /step`, use `Content-Type: application/json`.

### `GET /`

- **Description:** Returns service status.
- **Example request:**

```bash
curl -X GET http://localhost:7860/
```

- **Example response:**

```json
{"status":"ok"}
```

### `GET /reset`

- **Description:** Starts a new episode and returns the initial observation.
- **Example request:**

```bash
curl -X GET http://localhost:7860/reset
```

- **Example response (simplified):**

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

- **Description:** Applies an action and returns transition data.
- **Example request:**

```bash
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "report_vulnerability",
    "vulnerability_type": "SQL Injection",
    "line": 1
  }'
```

- **Minimum accepted payload fields:**

```json
{
  "action_type": "report_vulnerability",
  "vulnerability_type": "SQL Injection",
  "line": 1
}
```

- **Example response (simplified):**

```json
{
  "observation": {"task_id": "easy_sql_injection_01", "...": "..."},
  "reward": 0.72,
  "done": false,
  "info": {"done_reason": "action_graded", "...": "..."}
}
```

### `GET /health`

- **Description:** Returns health status.
- **Example request:**

```bash
curl -X GET http://localhost:7860/health
```

- **Example response:**

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

Configuration behavior:

- If `API_BASE_URL`, `MODEL_NAME`, and `HF_TOKEN` are set, inference can run in API mode.
- If they are not set, the baseline uses deterministic mock behavior.
- Keep `HF_TOKEN` out of git-tracked files; prefer local environment or secret management.

Example:

```env
API_BASE_URL=https://api-inference.huggingface.co/v1
MODEL_NAME=deepseek-ai/DeepSeek-R1:fastest
HF_TOKEN=hf_your_token_here
STRICT_MODE=0
```

---

## 🧪 Example Usage

Set a reusable base URL:

```bash
BASE_URL=http://localhost:7860
```

### Reset an episode

```bash
curl -X GET $BASE_URL/reset
```

### Submit one step action

```bash
curl -X POST $BASE_URL/step \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "report_vulnerability",
    "vulnerability_type": "SQL Injection",
    "line": 1
  }'
```

---

## 📈 Evaluation / Results

- Rewards are generated deterministically by rule-based grading.
- Step output includes a detailed `info.score_breakdown` structure.
- Each step reward is bounded to `[0, 1]` by the grader.
- Episode-level evaluation is summarized with `final_score` in baseline runs.
- `STRICT_MODE` controls stricter evaluation behavior for more conservative scoring.

Baseline summary metric:

```text
final_score = average(step_rewards), then bounded to [0, 1]
```

Note: this is a per-step average metric, not a cumulative-sum metric.

---

## 🚀 Deployment

### Local API deployment

```bash
uvicorn app.main:app --host 0.0.0.0 --port 7860
```

### Docker deployment

```bash
docker build -t code-security-env .
docker run --rm -p 7860:7860 code-security-env
```

### Hugging Face Space deployment

- Repository is configured for Hugging Face **Docker Space** hosting.
- Runtime metadata is defined in `openenv.yaml`.
- Live host format: `https://<owner>-<space-name>.hf.space`

---

## 🧾 OpenEnv Compliance

This project includes OpenEnv metadata and API behavior aligned for validator compatibility:

- `openenv.yaml` defines OpenEnv-compatible entrypoint and API contract.
- `/reset` supports **GET** and **POST** for validator/tooling compatibility.
- `/step` supports deterministic action evaluation with typed output fields.
- Deployment settings define Docker runtime and port configuration.

---

## ⚙️ Setup Instructions

### Prerequisites

- Python 3.11+ recommended
- Docker (optional, for containerized runs)

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

Local API base URL:

```text
http://localhost:7860
```

### Docker Setup

1. Build the image.
2. Run the container.

```bash
docker build -t code-security-env .
docker run --rm -p 7860:7860 code-security-env
```

Docker API base URL:

```text
http://localhost:7860
```

---

## ✅ Conclusion

CodeSecurityAuditEnv provides a deterministic, API-first benchmark for evaluating multi-step security reasoning over code.

With typed interfaces, reproducible scoring, and container-ready deployment, it can be used consistently across local testing, automated evaluation workflows, and hosted runtime environments.

For deployment verification, confirm `GET /`, `GET /reset`, `POST /step`, and `GET /health` return expected responses after each release.
