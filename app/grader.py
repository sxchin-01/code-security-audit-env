from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Action, TaskSpec, VulnerabilityType


@dataclass(frozen=True)
class GradeResult:
    """Deterministic grading output for one action against one task."""

    reward: float
    breakdown: dict[str, float]
    done_reason: str


# Keywords are used for deterministic lexical checks in explanation/fix quality.
_VULN_KEYWORDS: dict[VulnerabilityType, set[str]] = {
    VulnerabilityType.SQL_INJECTION: {
        "sql",
        "injection",
        "query",
        "parameterized",
        "parameter",
        "sanitize",
        "prepared",
    },
    VulnerabilityType.XSS: {"xss", "script", "html", "escape", "sanitize", "encoding"},
    VulnerabilityType.HARDCODED_SECRET: {
        "secret",
        "password",
        "credential",
        "token",
        "env",
        "vault",
    },
    VulnerabilityType.IMPROPER_VALIDATION: {
        "validate",
        "validation",
        "input",
        "path",
        "traversal",
        "normalize",
        "allowlist",
    },
    VulnerabilityType.WEAK_HASHING: {
        "hash",
        "md5",
        "bcrypt",
        "argon2",
        "salt",
        "password",
    },
    VulnerabilityType.PATH_TRAVERSAL: {
        "path",
        "traversal",
        "normalize",
        "base",
        "directory",
        "allowlist",
    },
    VulnerabilityType.INSECURE_DESERIALIZATION: {
        "deserialize",
        "deserialization",
        "pickle",
        "json",
        "schema",
        "untrusted",
    },
    VulnerabilityType.SSRF: {
        "ssrf",
        "url",
        "request",
        "allowlist",
        "internal",
        "ip",
        "host",
    },
    VulnerabilityType.NONE: set(),
}


def _normalize_text(value: str) -> str:
    return value.strip().lower()


def _tokenize(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9_]+", _normalize_text(value)))


def _count_keyword_hits(text: str, keywords: set[str]) -> int:
    tokens = _tokenize(text)
    return len(tokens.intersection(keywords))


def _explanation_score(explanation: str, expected_vuln: VulnerabilityType) -> float:
    text = _normalize_text(explanation)
    if not text:
        return 0.0

    # Must be minimally descriptive to get credit.
    if len(text) < 20:
        return 0.05

    hits = _count_keyword_hits(text, _VULN_KEYWORDS.get(expected_vuln, set()))
    if hits >= 4:
        return 0.2
    if hits == 3:
        return 0.16
    if hits == 2:
        return 0.12
    if hits == 1:
        return 0.08
    return 0.05


def _fix_score(fix: str, task: TaskSpec) -> float:
    text = _normalize_text(fix)
    if not text:
        return 0.0

    if len(text) < 20:
        return 0.05

    expected_tokens = _tokenize(task.expected_fix)
    vuln_tokens = _VULN_KEYWORDS.get(task.vulnerability_type, set())
    candidate_tokens = _tokenize(text)

    overlap_expected = len(candidate_tokens.intersection(expected_tokens))
    overlap_vuln = len(candidate_tokens.intersection(vuln_tokens))

    # Deterministic shaping: both direct overlap and domain-aware overlap matter.
    if overlap_expected >= 4 or (overlap_expected >= 2 and overlap_vuln >= 2):
        return 0.2
    if overlap_expected >= 3 or overlap_vuln >= 3:
        return 0.16
    if overlap_expected >= 2 or overlap_vuln >= 2:
        return 0.12
    if overlap_expected >= 1 or overlap_vuln >= 1:
        return 0.08
    return 0.05


def _line_score(predicted_line: int, expected_line: int) -> float:
    if predicted_line == expected_line:
        return 0.2
    if abs(predicted_line - expected_line) == 1:
        return 0.1
    return 0.0


def _irrelevant_penalty(action: Action, vuln_correct: bool) -> float:
    explanation_text = _normalize_text(action.explanation)
    fix_text = _normalize_text(action.fix)

    # Penalize empty/irrelevant responses, especially when core classification is wrong.
    if not explanation_text and not fix_text:
        return -0.2

    low_signal = (len(explanation_text) < 10) and (len(fix_text) < 10)
    if low_signal and not vuln_correct:
        return -0.2
    if low_signal:
        return -0.1
    return 0.0


def grade_action(action: Action, task: TaskSpec) -> GradeResult:
    """
    Grade a single action deterministically.

    Reward design (continuous, then clamped to [0.0, 1.0]):
    - vulnerability correctness: +0.4 (exact), else -0.3
    - line accuracy: +0.2 exact, +0.1 if off by 1
    - explanation quality: +0.0 to +0.2
    - fix quality: +0.0 to +0.2
    - irrelevant penalty: up to -0.2
    """

    vuln_correct = action.vulnerability_type == task.vulnerability_type
    vulnerability_component = 0.4 if vuln_correct else -0.3

    line_component = _line_score(action.line_number, task.vulnerable_line)
    explanation_component = _explanation_score(action.explanation, task.vulnerability_type)
    fix_component = _fix_score(action.fix, task)
    irrelevant_component = _irrelevant_penalty(action, vuln_correct)

    raw_reward = (
        vulnerability_component
        + line_component
        + explanation_component
        + fix_component
        + irrelevant_component
    )

    reward = max(0.0, min(1.0, raw_reward))

    breakdown = {
        "vulnerability": round(vulnerability_component, 4),
        "line": round(line_component, 4),
        "explanation": round(explanation_component, 4),
        "fix": round(fix_component, 4),
        "irrelevant_penalty": round(irrelevant_component, 4),
        "raw_total": round(raw_reward, 4),
        "final_reward": round(reward, 4),
    }

    done_reason = "action_graded"
    return GradeResult(reward=reward, breakdown=breakdown, done_reason=done_reason)
