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

CodeSecurityAuditEnv is an OpenEnv-compatible reinforcement learning environment for evaluating LLM security reasoning on source code.

## Project Overview

CodeSecurityAuditEnv is designed to benchmark how well LLMs can detect and remediate security vulnerabilities in realistic code snippets.

Why this matters:

- LLMs are increasingly used for code generation and code review.
- Security reasoning quality is often inconsistent and hard to measure.
- Existing evaluation setups usually focus on one-shot accuracy, not multi-step reasoning.

Key idea:

- Simulate real-world vulnerability analysis as a multi-step RL-style interaction.
- Evaluate both vulnerability detection and remediation quality with deterministic scoring.

## Key Features

- Multi-step RL environment (`reset -> step -> state`)
- 12 deterministic security tasks from easy to hard
- Multi-vulnerability support in hard-tier scenarios
- Deterministic grading and reproducible episodes
- Strict vs tolerant evaluation modes
- Non-saturating per-step metric (`final_score`, equivalent to avg-step reward)
- Extensible vulnerability type system for new security categories

## Project Structure

```text
project/
|-- app/
|   |-- main.py        # FastAPI server
|   |-- env.py         # Environment logic
|   |-- models.py      # Pydantic schemas
|   |-- tasks.py       # Deterministic task dataset
|   |-- grader.py      # Deterministic reward grading
|-- inference.py       # Baseline LLM agent loop (HF or Gemini)
|-- openenv.yaml       # OpenEnv metadata
|-- requirements.txt
|-- Dockerfile
|-- README.md
```

## Environment Design

High-level loop:

- Agent proposes an action.
- Environment validates and applies the action to the active task.
- Grader computes deterministic reward and breakdown.
- Environment returns next observation, reward, and termination signal.

Pipeline:

- `Agent -> Environment -> Grader -> Reward -> Next Step`

Core APIs:

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

- `action_type: report_vulnerability | suggest_fix | no_vulnerability`
- `vulnerability_type:`
  `SQL Injection | XSS | Hardcoded Secret | Improper Validation | Weak Hashing |`
  `Command Injection | Path Traversal | Broken Authentication | Missing Rate Limiting |`
  `Sensitive Data Exposure | Insecure Debug Configuration | Insecure Deserialization |`
  `SSRF | API Key Leakage | CORS Misconfiguration | OAuth Redirect Misvalidation |`
  `Prompt Injection | AI Generated Insecure Code | None`
- `vulnerability_label: str | None`
- `line_number: int`
- `explanation: str`
- `fix: str`

## Tasks

The benchmark currently contains 12 deterministic Python tasks:

- Easy: `2`
- Medium: `5`
- Hard: `5`

Representative vulnerability categories include:

- SQL Injection
- SSRF
- Command Injection
- Path Traversal
- Insecure Deserialization
- Authentication flaws
- Rate limiting failures
- Sensitive data exposure
- Prompt injection

Each task uses canonical `vulnerabilities[]` ground truth with:

- `vuln_id`
- `type`
- `line`
- `severity` (`low|medium|high|critical`)
- `accepted_fixes` and optional aliases

Real-world relevance:

- Tasks mirror production failure modes seen in APIs, authentication flows, logging, and LLM-integrated systems.
- Hard tasks include multiple vulnerabilities in one episode to evaluate prioritization and multi-step handling.

## Reward Function

Reward grading is deterministic and continuous, then clamped to `[0.0, 1.0]` per step.

Reward components:

- Vulnerability match quality (exact or related)
- Line accuracy
- Explanation quality (keyword + causality signal)
- Fix quality (accepted-fix overlap + secure-pattern signal)
- Response format quality

Behavioral characteristics:

- Partial credit for related but imperfect findings
- Penalties for low-signal, irrelevant, or repeated incorrect attempts
- Multi-step accumulation across the episode
- Difficulty-aware calibration (`easy|medium|hard`)

Episode progression is deterministic; scoring has no randomness.

## Evaluation Methodology

Primary metric:

- `final_score = clamp(total_reward / num_steps, 0, 1)`

Why this metric:

- Prevents score saturation that occurs with clamped cumulative totals.
- Preserves performance differences between strict and tolerant settings.
- Reflects true per-step reasoning quality over the full episode.

Evaluation modes:

- Tolerant mode: training-friendly, more lenient grading.
- Strict mode: leaderboard-style, stricter quality thresholds.

## Example Output

```text
Task: hard_prompt_injection_chain_01
final_score: 0.78 (strict)

Average final_score (strict): 0.75
Average final_score (tolerant): 0.88
```

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

## How To Run

1. Clone repository:

```bash
git clone https://github.com/sxchin-01/code-security-audit-env.git
cd code-security-audit-env
```

2. Install dependencies:

Python version guidance:

- Recommended: `Python 3.11`
- Supported: `Python 3.10` to `Python 3.13`
- `Python 3.14` may fail for some native dependencies (for example `pydantic-core`) depending on wheel availability.

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

3. Configure environment variables:

Copy `.env.example` to `.env` and set provider keys:

```bash
cp .env.example .env
```

Contents of `.env`:
```
LLM_PROVIDER=gemini
STRICT_MODE=0

# For Hugging Face (LLM_PROVIDER=hf)
HF_API_KEY=hf_your_token_here
HF_MODEL=deepseek-ai/DeepSeek-R1:fastest
HF_DEBUG_RESPONSE=0

# For Gemini (LLM_PROVIDER=gemini)
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.0-flash
GEMINI_DEBUG_RESPONSE=0
```

4. Run API server:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

5. Run evaluation script:

```bash
python inference.py
```

This loads `.env` automatically and prints per-task plus average `final_score`.

Optional: run both modes for comparison:

```bash
$env:STRICT_MODE="0"; python inference.py
$env:STRICT_MODE="1"; python inference.py
```

Optional: override provider/model at runtime:

```bash
$env:LLM_PROVIDER="gemini"; $env:GEMINI_MODEL="gemini-2.0-flash"; python inference.py
```

If using Hugging Face, ensure your token has permission to "Make calls to Inference Providers".

## Future Work

- Train RL agents directly on this environment rather than only using fixed policies.
- Expand task coverage with additional modern vulnerability classes and language targets.
- Integrate curated real-world vulnerability datasets and patch corpora.

## Conclusion

CodeSecurityAuditEnv provides a practical, reproducible benchmark for evaluating LLM security reasoning in realistic coding workflows.

It is designed for:

- Robustness: deterministic grading and stable task ordering
- Reproducibility: no stochastic environment behavior
- Extensibility: typed schemas and expandable vulnerability taxonomy

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
