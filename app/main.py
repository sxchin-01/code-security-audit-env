from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException

from .env import CodeSecurityAuditEnv
from .models import Action, ResetResponse, StateResponse

app = FastAPI(
    title="CodeSecurityAuditEnv API",
    description="OpenEnv-compatible API for code security auditing RL tasks.",
    version="1.0.0",
)

env = CodeSecurityAuditEnv()


@app.get("/")
def root() -> dict[str, str]:
    """Basic liveness endpoint for container platforms and browser checks."""

    return {"status": "ok"}


@app.api_route("/reset", methods=["GET", "POST"], response_model=ResetResponse)
def reset_env() -> ResetResponse:
    """Start a new episode and return the initial observation."""

    observation = env.reset()
    return ResetResponse(observation=observation)


@app.post("/step")
def step_env(payload: dict[str, Any]) -> dict:
    """Apply one action and return (observation, reward, done, info)."""

    action_payload = payload.get("action") if isinstance(payload.get("action"), dict) else payload
    if not isinstance(action_payload, dict):
        raise HTTPException(status_code=400, detail="Invalid action payload: expected JSON object")

    adapted_payload = {
        "action_type": action_payload.get("action_type"),
        "vulnerability_type": action_payload.get("vulnerability_type"),
        "line_number": action_payload.get("line_number", action_payload.get("line")),
        "explanation": action_payload.get("explanation", ""),
        "fix": action_payload.get("fix", ""),
    }

    try:
        action = Action.model_validate(adapted_payload)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid action payload: {exc}") from exc

    try:
        observation, reward, done, info = env.step(action)
        observation_dump = observation.model_dump()
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "observation": observation_dump,
        "reward": reward,
        "done": done,
        "info": info,
    }


@app.get("/state", response_model=StateResponse)
def state_env() -> StateResponse:
    """Return current serialized environment state."""

    return StateResponse(state=env.state())


@app.get("/health")
def health() -> dict[str, str]:
    """Lightweight health check for container platforms."""

    return {"status": "ok"}
