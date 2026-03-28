from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Difficulty(str, Enum):
    """Supported task difficulty tiers."""

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


class ActionType(str, Enum):
    """Agent action categories supported by the environment."""

    REPORT_VULNERABILITY = "report_vulnerability"
    SUGGEST_FIX = "suggest_fix"


class VulnerabilityType(str, Enum):
    """Canonical vulnerability labels used for deterministic grading."""

    SQL_INJECTION = "SQL Injection"
    XSS = "XSS"
    HARDCODED_SECRET = "Hardcoded Secret"
    IMPROPER_VALIDATION = "Improper Validation"
    WEAK_HASHING = "Weak Hashing"
    PATH_TRAVERSAL = "Path Traversal"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    SSRF = "SSRF"
    NONE = "None"


class ActionHistoryItem(BaseModel):
    """Compact history item to provide action trace context in observations."""

    model_config = ConfigDict(extra="forbid")

    action_type: ActionType
    vulnerability_type: VulnerabilityType
    line_number: int = Field(ge=1)
    explanation: str = Field(default="")
    fix: str = Field(default="")
    reward: float = Field(ge=0.0, le=1.0)


class Observation(BaseModel):
    """Typed observation returned by reset() and step()."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1)
    language: str = Field(min_length=1)
    context: str = Field(default="")
    task_id: str = Field(min_length=1)
    difficulty: Difficulty
    history: list[ActionHistoryItem] | None = None


class Action(BaseModel):
    """Typed action accepted by step(action)."""

    model_config = ConfigDict(extra="forbid")

    action_type: ActionType
    vulnerability_type: VulnerabilityType
    line_number: int = Field(ge=1)
    explanation: str = Field(default="")
    fix: str = Field(default="")


class TaskSpec(BaseModel):
    """Ground-truth task representation used by task dataset and grader."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(min_length=1)
    code: str = Field(min_length=1)
    language: str = Field(min_length=1)
    context: str = Field(default="")
    vulnerability_type: VulnerabilityType
    vulnerable_line: int = Field(ge=1)
    expected_fix: str = Field(min_length=1)
    difficulty: Difficulty


class StepInfo(BaseModel):
    """Structured metadata returned in step(...) info payload."""

    model_config = ConfigDict(extra="forbid")

    score_breakdown: dict[str, float] = Field(default_factory=dict)
    expected_vulnerability: VulnerabilityType
    expected_line: int = Field(ge=1)
    done_reason: str


class StepResult(BaseModel):
    """Helper schema for internal and API serialization of step outputs."""

    model_config = ConfigDict(extra="forbid")

    observation: Observation
    reward: float = Field(ge=0.0, le=1.0)
    done: bool
    info: StepInfo


class EnvState(BaseModel):
    """Serializable environment state returned by state()."""

    model_config = ConfigDict(extra="forbid")

    episode_index: int = Field(ge=0)
    task_cursor: int = Field(ge=0)
    current_task: TaskSpec | None = None
    last_observation: Observation | None = None
    total_reward: float = Field(ge=0.0)
    done: bool
    history: list[ActionHistoryItem] = Field(default_factory=list)


class ResetResponse(BaseModel):
    """API response wrapper for POST /reset."""

    model_config = ConfigDict(extra="forbid")

    observation: Observation


class StepRequest(BaseModel):
    """API request schema for POST /step."""

    model_config = ConfigDict(extra="forbid")

    action: Action


class StateResponse(BaseModel):
    """API response wrapper for GET /state."""

    model_config = ConfigDict(extra="forbid")

    state: EnvState


class OpenEnvMetadata(BaseModel):
    """Typed helper for generating/validating openenv.yaml content."""

    model_config = ConfigDict(extra="allow")

    name: str
    description: str
    version: str
    observation_schema: dict[str, Any]
    action_schema: dict[str, Any]
