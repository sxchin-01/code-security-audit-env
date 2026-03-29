from __future__ import annotations

from dataclasses import dataclass

from .grader import grade_action
from .models import (
    Action,
    ActionHistoryItem,
    Difficulty,
    EnvState,
    Observation,
    StepInfo,
    StepResult,
    TaskSpec,
    VulnerabilityType,
)
from .tasks import get_all_tasks


@dataclass
class EnvConfig:
    """Runtime configuration for deterministic episode handling."""

    max_steps_per_episode: int = 4
    include_history_in_observation: bool = True
    strict_mode: bool = False
    # Optional reward profile overrides keyed by difficulty, e.g.:
    # {"hard": {"wrong_vulnerability_penalty": 1.25}}
    difficulty_profile_overrides: dict[str, dict[str, float]] | None = None


class CodeSecurityAuditEnv:
    """
    OpenEnv-compatible RL environment for code security auditing.

    Core APIs:
    - reset() -> Observation
    - step(action) -> tuple[Observation, float, bool, dict]
    - state() -> EnvState

    Determinism:
    - Tasks are loaded once in fixed order.
    - reset() advances task cursor in stable sequence.
    - No randomness in grading or transitions.
    """

    def __init__(self, config: EnvConfig | None = None) -> None:
        self._config = config or EnvConfig()
        self._tasks: list[TaskSpec] = get_all_tasks()
        if not self._tasks:
            raise ValueError("Task dataset is empty. At least one task is required.")

        self._episode_index: int = 0
        self._task_cursor: int = 0
        self._step_count: int = 0
        self._done: bool = True

        self._current_task: TaskSpec | None = None
        self._history: list[ActionHistoryItem] = []
        self._last_observation: Observation | None = None
        self._total_reward: float = 0.0
        self._addressed_vulnerability_ids: set[str] = set()
        self._difficulty_profile_overrides = self._normalize_profile_overrides(
            self._config.difficulty_profile_overrides
        )

    def _normalize_profile_overrides(
        self,
        raw: dict[str, dict[str, float]] | None,
    ) -> dict[Difficulty, dict[str, float]]:
        if not raw:
            return {}

        normalized: dict[Difficulty, dict[str, float]] = {}
        for difficulty_key, values in raw.items():
            try:
                difficulty = Difficulty(difficulty_key)
            except ValueError:
                continue
            if not isinstance(values, dict):
                continue
            sanitized = {k: float(v) for k, v in values.items() if isinstance(v, (int, float))}
            if sanitized:
                normalized[difficulty] = sanitized
        return normalized

    def _remaining_vulnerability_ids(self) -> list[str]:
        if self._current_task is None:
            return []
        remaining = [
            vuln.vuln_id
            for vuln in self._current_task.vulnerabilities
            if vuln.vuln_id not in self._addressed_vulnerability_ids
        ]
        return remaining

    def _next_expected_vulnerability(self) -> tuple[VulnerabilityType | None, int | None]:
        if self._current_task is None:
            return (None, None)
        for vuln in self._current_task.vulnerabilities:
            if vuln.vuln_id not in self._addressed_vulnerability_ids:
                return (vuln.type, vuln.line)
        return (None, None)

    def _build_observation(self) -> Observation:
        if self._current_task is None:
            raise RuntimeError("Environment has no active task. Call reset() first.")

        history = list(self._history) if self._config.include_history_in_observation else None
        return Observation(
            code=self._current_task.code,
            language=self._current_task.language,
            context=self._current_task.context,
            task_id=self._current_task.task_id,
            difficulty=self._current_task.difficulty,
            history=history,
        )

    def reset(self) -> Observation:
        """Start a new episode on the next task and return the initial observation."""

        self._current_task = self._tasks[self._task_cursor]
        self._task_cursor = (self._task_cursor + 1) % len(self._tasks)

        self._episode_index += 1
        self._step_count = 0
        self._done = False
        self._history = []
        self._total_reward = 0.0
        self._addressed_vulnerability_ids = set()

        self._last_observation = self._build_observation()
        return self._last_observation

    def step(self, action: Action) -> tuple[Observation, float, bool, dict]:
        """
        Evaluate one action and return OpenEnv tuple:
        (observation, reward, done, info)
        """

        if self._current_task is None or self._done:
            raise RuntimeError("Episode is not active. Call reset() before step().")

        self._step_count += 1
        grade = grade_action(
            action,
            self._current_task,
            addressed_ids=set(self._addressed_vulnerability_ids),
            attempt_index=self._step_count,
            profile_overrides=self._difficulty_profile_overrides,
            strict_mode=self._config.strict_mode,
        )

        if grade.newly_addressed and grade.matched_vulnerability_id:
            self._addressed_vulnerability_ids.add(grade.matched_vulnerability_id)

        self._total_reward += grade.reward
        self._history.append(
            ActionHistoryItem(
                action_type=action.action_type,
                vulnerability_type=action.vulnerability_type,
                line_number=action.line_number,
                explanation=action.explanation,
                fix=action.fix,
                reward=grade.reward,
            )
        )

        reached_max_steps = self._step_count >= self._config.max_steps_per_episode
        remaining_ids = self._remaining_vulnerability_ids()
        all_addressed = len(remaining_ids) == 0
        self._done = bool(reached_max_steps or all_addressed)

        done_reason = (
            "all_vulnerabilities_addressed"
            if all_addressed
            else "max_steps_reached"
            if reached_max_steps
            else grade.done_reason
        )

        self._last_observation = self._build_observation()
        expected_vuln_value, expected_line = self._next_expected_vulnerability()
        info_model = StepInfo(
            score_breakdown=grade.breakdown,
            expected_vulnerability=expected_vuln_value,
            expected_line=expected_line,
            matched_vulnerability=grade.matched_vulnerability_id,
            newly_addressed=grade.newly_addressed,
            addressed_vulnerabilities=sorted(self._addressed_vulnerability_ids),
            remaining_vulnerabilities=remaining_ids,
            done_reason=done_reason,
        )
        result = StepResult(
            observation=self._last_observation,
            reward=grade.reward,
            done=self._done,
            info=info_model,
        )

        return (
            result.observation,
            result.reward,
            result.done,
            result.info.model_dump(),
        )

    def state(self) -> EnvState:
        """Return serializable current environment state."""

        return EnvState(
            episode_index=self._episode_index,
            task_cursor=self._task_cursor,
            current_task=self._current_task,
            last_observation=self._last_observation,
            total_reward=round(self._total_reward, 4),
            done=self._done,
            step_count=self._step_count,
            addressed_vulnerabilities=sorted(self._addressed_vulnerability_ids),
            remaining_vulnerabilities=self._remaining_vulnerability_ids(),
            history=list(self._history),
        )
