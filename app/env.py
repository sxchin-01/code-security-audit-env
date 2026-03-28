from __future__ import annotations

from dataclasses import dataclass

from .grader import grade_action
from .models import (
    Action,
    ActionHistoryItem,
    EnvState,
    Observation,
    StepInfo,
    StepResult,
    TaskSpec,
)
from .tasks import get_all_tasks


@dataclass
class EnvConfig:
    """Runtime configuration for deterministic episode handling."""

    max_steps_per_episode: int = 2
    include_history_in_observation: bool = True


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
        grade = grade_action(action, self._current_task)

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
        # If the agent submits a concrete fix, we consider the audit cycle complete.
        is_terminal_action = action.action_type.value == "suggest_fix"
        self._done = bool(reached_max_steps or is_terminal_action)

        done_reason = (
            "terminal_action"
            if is_terminal_action
            else "max_steps_reached"
            if reached_max_steps
            else grade.done_reason
        )

        self._last_observation = self._build_observation()
        info_model = StepInfo(
            score_breakdown=grade.breakdown,
            expected_vulnerability=self._current_task.vulnerability_type,
            expected_line=self._current_task.vulnerable_line,
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
            history=list(self._history),
        )
