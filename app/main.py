from __future__ import annotations

from fastapi import FastAPI, HTTPException

from .env import CodeSecurityAuditEnv
from .models import Action, ResetResponse, StateResponse, StepRequest

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


@app.post("/reset", response_model=ResetResponse)
def reset_env() -> ResetResponse:
    """Start a new episode and return the initial observation."""

    observation = env.reset()
    return ResetResponse(observation=observation)


@app.post("/step")
def step_env(payload: StepRequest) -> dict:
    """Apply one action and return (observation, reward, done, info)."""

    try:
        observation, reward, done, info = env.step(payload.action)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "observation": observation.model_dump(),
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
