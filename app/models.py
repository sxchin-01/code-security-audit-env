from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Difficulty(str, Enum):
    """Supported task difficulty tiers."""

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


class ActionType(str, Enum):
    """Agent action categories supported by the environment."""

    REPORT_VULNERABILITY = "report_vulnerability"
    SUGGEST_FIX = "suggest_fix"
    NO_VULNERABILITY = "no_vulnerability"


class VulnerabilityType(str, Enum):
    """Canonical vulnerability labels used for deterministic grading."""

    SQL_INJECTION = "SQL Injection"
    XSS = "XSS"
    HARDCODED_SECRET = "Hardcoded Secret"
    IMPROPER_VALIDATION = "Improper Validation"
    WEAK_HASHING = "Weak Hashing"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    BROKEN_AUTHENTICATION = "Broken Authentication"
    RATE_LIMITING = "Missing Rate Limiting"
    SENSITIVE_DATA_EXPOSURE = "Sensitive Data Exposure"
    DEBUG_CONFIGURATION = "Insecure Debug Configuration"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    SSRF = "SSRF"
    API_KEY_LEAKAGE = "API Key Leakage"
    CORS_MISCONFIGURATION = "CORS Misconfiguration"
    OAUTH_REDIRECT_MISVALIDATION = "OAuth Redirect Misvalidation"
    PROMPT_INJECTION = "Prompt Injection"
    AI_GENERATED_INSECURE_CODE = "AI Generated Insecure Code"
    NONE = "None"


class Severity(str, Enum):
    """Security issue severity used for weighted progression and penalties."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilitySpec(BaseModel):
    """Canonical per-vulnerability ground truth inside a task."""

    model_config = ConfigDict(extra="forbid")

    vuln_id: str = Field(min_length=1)
    type: VulnerabilityType
    line: int = Field(ge=1)
    severity: Severity = Severity.MEDIUM
    accepted_fixes: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)


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
    vulnerability_label: str | None = None
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
    logs: list[str] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilitySpec] = Field(default_factory=list)
    # Legacy fields kept for backward compatibility.
    vulnerability_type: VulnerabilityType | None = None
    vulnerable_line: int | None = Field(default=None, ge=1)
    expected_fix: str | None = None
    difficulty: Difficulty

    @model_validator(mode="after")
    def ensure_vulnerabilities(self) -> TaskSpec:
        # Backward compatibility: if legacy single-vulnerability fields are provided,
        # synthesize a canonical vulnerabilities list.
        if not self.vulnerabilities:
            if (
                self.vulnerability_type is not None
                and self.vulnerable_line is not None
                and self.expected_fix
            ):
                self.vulnerabilities = [
                    VulnerabilitySpec(
                        vuln_id=f"{self.task_id}_v1",
                        type=self.vulnerability_type,
                        line=self.vulnerable_line,
                        severity=Severity.MEDIUM,
                        accepted_fixes=[self.expected_fix],
                    )
                ]
            else:
                raise ValueError(
                    "TaskSpec requires either vulnerabilities[] or full legacy fields "
                    "(vulnerability_type, vulnerable_line, expected_fix)."
                )

        # Keep legacy fields populated from the first canonical vulnerability for compatibility.
        if self.vulnerability_type is None:
            self.vulnerability_type = self.vulnerabilities[0].type
        if self.vulnerable_line is None:
            self.vulnerable_line = self.vulnerabilities[0].line
        if not self.expected_fix:
            first_fixes = self.vulnerabilities[0].accepted_fixes
            self.expected_fix = first_fixes[0] if first_fixes else "Provide secure remediation."

        return self


class StepInfo(BaseModel):
    """Structured metadata returned in step(...) info payload."""

    model_config = ConfigDict(extra="forbid")

    score_breakdown: dict[str, float] = Field(default_factory=dict)
    expected_vulnerability: VulnerabilityType | None = None
    expected_line: int | None = Field(default=None, ge=1)
    matched_vulnerability: str | None = None
    newly_addressed: bool = False
    addressed_vulnerabilities: list[str] = Field(default_factory=list)
    remaining_vulnerabilities: list[str] = Field(default_factory=list)
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
    step_count: int = Field(ge=0)
    addressed_vulnerabilities: list[str] = Field(default_factory=list)
    remaining_vulnerabilities: list[str] = Field(default_factory=list)
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
