---
title: CodeSecurityAuditEnv
emoji: shield
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
pinned: false
---

# CodeSecurityAuditEnv

CodeSecurityAuditEnv is an OpenEnv-compatible reinforcement learning environment for code security auditing. Each episode provides a vulnerable code snippet and expects the agent to:

1. Identify vulnerability type
2. Identify vulnerable line number
3. Explain the issue
4. Suggest a fix

The environment is deterministic, typed with Pydantic, and exposed through FastAPI.

## Project Structure

```text
project/
|-- app/
|   |-- main.py        # FastAPI server
|   |-- env.py         # Environment logic
|   |-- models.py      # Pydantic schemas
|   |-- tasks.py       # Deterministic task dataset
|   |-- grader.py      # Deterministic reward grading
|-- inference.py       # Baseline OpenAI agent loop
|-- openenv.yaml       # OpenEnv metadata
|-- requirements.txt
|-- Dockerfile
|-- README.md
```

## Environment Design

- Name: `CodeSecurityAuditEnv`
- Core APIs:
  - `reset() -> Observation`
  - `step(action) -> (observation, reward, done, info)`
  - `state() -> EnvState`

### Observation Model (Typed)

- `code: str`
- `language: str`
- `context: str`
- `task_id: str`
- `difficulty: easy | medium | hard`
- `history: list[ActionHistoryItem] | None`

### Action Model (Typed)

- `action_type: report_vulnerability | suggest_fix`
- `vulnerability_type: SQL Injection | XSS | Hardcoded Secret | ... | None`
- `line_number: int`
- `explanation: str`
- `fix: str`

## Tasks

The dataset includes multiple vulnerabilities across three difficulty levels:

- Easy: SQL Injection, Hardcoded Secret
- Medium: Improper Validation, Weak Hashing
- Hard: SSRF, Insecure Deserialization

All tasks have explicit ground truth (`vulnerability_type`, `vulnerable_line`, `expected_fix`) for deterministic scoring.

## Reward Function

Reward is continuous and clamped to `[0.0, 1.0]`.

Base shaping:

- Correct vulnerability: `+0.4`
- Correct line: `+0.2` (or `+0.1` if off-by-one)
- Explanation quality: up to `+0.2`
- Fix quality: up to `+0.2`

Penalties:

- Wrong vulnerability: `-0.3`
- Irrelevant/empty action: up to `-0.2`

Scoring is deterministic (no randomness).

## FastAPI Endpoints

- `POST /reset`
- `POST /step`
- `GET /state`
- `GET /health`

### Example Request

```bash
curl -X POST http://localhost:8000/reset
```

```bash
curl -X POST http://localhost:8000/step \
  -H "Content-Type: application/json" \
  -d '{
    "action": {
      "action_type": "suggest_fix",
      "vulnerability_type": "SQL Injection",
      "line_number": 7,
      "explanation": "User input is concatenated into a SQL query and can alter query logic.",
      "fix": "Use parameterized queries with placeholders and bound parameters."
    }
  }'
```

```bash
curl http://localhost:8000/state
```

## Local Setup

Python version:

- Recommended: `Python 3.11`
- Supported: `Python 3.10` to `Python 3.13`
- `Python 3.14` may fail for some native dependencies (for example `pydantic-core`) depending on wheel availability.

1. Install dependencies:

```bash
pip install -r requirements.txt
```

If your default Python is `3.14` on Windows, create a 3.11 virtual environment first:

```bash
py -3.11 -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

2. Configure environment (secure API keys):

Copy `.env.example` to `.env` and fill in your Hugging Face token:

```bash
cp .env.example .env
# Edit .env and set your real HF_API_KEY
```

Contents of `.env`:
```
HF_API_KEY=hf_your_token_here
HF_MODEL=deepseek-ai/DeepSeek-R1:fastest
HF_DEBUG_RESPONSE=0
```

The `.env` file is automatically excluded from git (`see .gitignore`) so secrets are never committed.

3. Run API server:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

4. Run baseline inference agent:

```bash
python inference.py
```

This will load your `.env` file automatically.

Optional: Override model at runtime (without modifying `.env`):

```bash
$env:HF_MODEL="openai/gpt-oss-120b:fastest"; python inference.py
```

Note: If your token is fine-grained, ensure it has permission to "Make calls to Inference Providers".

## Docker

Build image:

```bash
docker build -t code-security-audit-env .
```

Run container:

```bash
docker run --rm -p 7860:7860 code-security-audit-env
```

Open API locally at `http://localhost:7860`.

### Hugging Face Spaces (Docker)

This repository is compatible with Spaces Docker runtime:

1. Push this project to a Hugging Face Space configured with `SDK: Docker`.
2. Spaces will build `Dockerfile` automatically.
3. The app binds to `$PORT` (default `7860`), which matches Spaces requirements.
4. Use Space secrets for sensitive values (for example `HF_API_KEY` if baseline inference is used in Space).

## Reproducibility Notes

- Task ordering is fixed.
- Reset progression is deterministic.
- Reward computation has no stochastic elements.
- Baseline uses `temperature=0` for consistent model behavior.
