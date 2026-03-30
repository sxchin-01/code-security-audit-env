from __future__ import annotations

from pathlib import Path
import importlib
from typing import Any

from fastapi import FastAPI, HTTPException

# Make this module behave like a package proxy so imports like app.env
# resolve to the existing ./app package even though this file is named app.py.
__path__ = [str(Path(__file__).parent / "app")]

_env_module = importlib.import_module("app.env")
_models_module = importlib.import_module("app.models")

CodeSecurityAuditEnv = _env_module.CodeSecurityAuditEnv
Action = _models_module.Action

app = FastAPI(title="CodeSecurityAuditEnv Space API")
env = CodeSecurityAuditEnv()


@app.get("/")
def root() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/reset")
def reset() -> dict[str, Any]:
    observation = env.reset()
    return {"observation": observation.model_dump()}


@app.post("/step")
def step(action: dict[str, Any]) -> dict[str, Any]:
    try:
        parsed_action = Action.model_validate(action)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid action payload: {exc}") from exc

    observation, reward, done, info = env.step(parsed_action)
    return {
        "observation": observation.model_dump(),
        "reward": reward,
        "done": done,
        "info": info,
    }
