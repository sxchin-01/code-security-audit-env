from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .models import Action, ActionType, Difficulty, Severity, TaskSpec, VulnerabilitySpec, VulnerabilityType


@dataclass(frozen=True)
class GradeResult:
    """Deterministic grading output for one action against one task."""

    reward: float
    breakdown: dict[str, float]
    done_reason: str
    matched_vulnerability_id: str | None = None
    newly_addressed: bool = False


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
    VulnerabilityType.API_KEY_LEAKAGE: {
        "api",
        "key",
        "secret",
        "token",
        "credential",
        "hardcoded",
        "logs",
    },
    VulnerabilityType.CORS_MISCONFIGURATION: {
        "cors",
        "origin",
        "wildcard",
        "credentials",
        "allowlist",
        "browser",
    },
    VulnerabilityType.OAUTH_REDIRECT_MISVALIDATION: {
        "oauth",
        "redirect",
        "allowlist",
        "state",
        "callback",
        "open",
    },
    VulnerabilityType.PROMPT_INJECTION: {
        "prompt",
        "injection",
        "instruction",
        "system",
        "tool",
        "untrusted",
        "llm",
    },
    VulnerabilityType.AI_GENERATED_INSECURE_CODE: {
        "ai",
        "generated",
        "unsafe",
        "execute",
        "model",
        "output",
        "sql",
    },
    VulnerabilityType.NONE: set(),
}

_VULN_SYNONYMS: dict[VulnerabilityType, set[str]] = {
    VulnerabilityType.SQL_INJECTION: {"sql injection", "sqli"},
    VulnerabilityType.XSS: {"xss", "cross site scripting", "cross-site scripting"},
    VulnerabilityType.HARDCODED_SECRET: {
        "hardcoded secret",
        "hardcoded password",
        "hardcoded credential",
    },
    VulnerabilityType.IMPROPER_VALIDATION: {"improper validation", "input validation"},
    VulnerabilityType.WEAK_HASHING: {"weak hashing", "insecure hash", "md5", "sha1"},
    VulnerabilityType.PATH_TRAVERSAL: {"path traversal", "directory traversal"},
    VulnerabilityType.INSECURE_DESERIALIZATION: {"insecure deserialization", "unsafe yaml", "pickle"},
    VulnerabilityType.SSRF: {"ssrf", "server side request forgery", "server-side request forgery"},
    VulnerabilityType.API_KEY_LEAKAGE: {"api key leakage", "secret leakage", "credential leak"},
    VulnerabilityType.CORS_MISCONFIGURATION: {"cors misconfiguration", "wildcard origin with credentials"},
    VulnerabilityType.OAUTH_REDIRECT_MISVALIDATION: {
        "oauth redirect misvalidation",
        "open redirect",
        "redirect uri validation",
    },
    VulnerabilityType.PROMPT_INJECTION: {"prompt injection", "instruction injection"},
    VulnerabilityType.AI_GENERATED_INSECURE_CODE: {"ai generated insecure code", "unsafe llm output"},
    VulnerabilityType.NONE: {"none", "no vulnerability"},
}

_RELATED_VULN_GROUPS: list[set[VulnerabilityType]] = [
    {VulnerabilityType.SQL_INJECTION, VulnerabilityType.AI_GENERATED_INSECURE_CODE},
    {VulnerabilityType.IMPROPER_VALIDATION, VulnerabilityType.PATH_TRAVERSAL},
    {VulnerabilityType.HARDCODED_SECRET, VulnerabilityType.API_KEY_LEAKAGE},
    {VulnerabilityType.PROMPT_INJECTION, VulnerabilityType.AI_GENERATED_INSECURE_CODE},
    {VulnerabilityType.OAUTH_REDIRECT_MISVALIDATION, VulnerabilityType.IMPROPER_VALIDATION},
]

_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.LOW: 0.75,
    Severity.MEDIUM: 1.0,
    Severity.HIGH: 1.1,
    Severity.CRITICAL: 1.2,
}


_DIFFICULTY_PROFILE: dict[Difficulty, dict[str, float]] = {
    # Easier tier: stronger signal for core correctness, lighter penalties.
    Difficulty.EASY: {
        "vulnerability_positive": 1.05,
        "line_positive": 1.05,
        "explanation_positive": 1.0,
        "fix_positive": 1.0,
        "format_positive": 1.0,
        "wrong_vulnerability_penalty": 0.85,
        "irrelevant_penalty": 0.9,
        "repeat_decay": 0.85,
        "critical_penalty": 0.8,
    },
    # Baseline tier.
    Difficulty.MEDIUM: {
        "vulnerability_positive": 1.0,
        "line_positive": 1.0,
        "explanation_positive": 1.0,
        "fix_positive": 1.0,
        "format_positive": 1.0,
        "wrong_vulnerability_penalty": 1.0,
        "irrelevant_penalty": 1.0,
        "repeat_decay": 1.0,
        "critical_penalty": 1.0,
    },
    # Hard tier: prioritize precise reasoning and remediation quality.
    Difficulty.HARD: {
        "vulnerability_positive": 0.95,
        "line_positive": 0.95,
        "explanation_positive": 1.1,
        "fix_positive": 1.1,
        "format_positive": 1.0,
        "wrong_vulnerability_penalty": 1.15,
        "irrelevant_penalty": 1.1,
        "repeat_decay": 1.1,
        "critical_penalty": 1.2,
    },
}


def _merged_difficulty_profile(
    difficulty: Difficulty,
    profile_overrides: dict[Difficulty, dict[str, float]] | None,
) -> dict[str, float]:
    base = dict(_DIFFICULTY_PROFILE[difficulty])
    if not profile_overrides:
        return base

    overrides_for_difficulty = profile_overrides.get(difficulty)
    if not overrides_for_difficulty:
        return base

    for key, value in overrides_for_difficulty.items():
        if key in base and value > 0:
            base[key] = value
    return base


def _normalize_text(value: str) -> str:
    return value.strip().lower()


def _tokenize(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9_]+", _normalize_text(value)))


def _count_keyword_hits(text: str, keywords: set[str]) -> int:
    tokens = _tokenize(text)
    return len(tokens.intersection(keywords))


def _resolve_predicted_type(action: Action) -> VulnerabilityType:
    label = _normalize_text(action.vulnerability_label or "")
    if not label:
        return action.vulnerability_type

    for vuln, aliases in _VULN_SYNONYMS.items():
        if label in aliases:
            return vuln
    return action.vulnerability_type


def _causality_hits(text: str) -> int:
    concepts = {
        "user",
        "input",
        "unsanitized",
        "untrusted",
        "attacker",
        "execute",
        "dangerous",
        "exfiltrate",
        "privilege",
    }
    return _count_keyword_hits(text, concepts)


def _unresolved_vulnerabilities(task: TaskSpec, addressed_ids: set[str]) -> list[VulnerabilitySpec]:
    return [v for v in task.vulnerabilities if v.vuln_id not in addressed_ids]


def _find_matching_vulnerability(
    *,
    predicted_type: VulnerabilityType,
    predicted_line: int,
    task: TaskSpec,
    addressed_ids: set[str],
) -> VulnerabilitySpec | None:
    candidates = [
        v for v in _unresolved_vulnerabilities(task, addressed_ids) if v.type == predicted_type
    ]
    if not candidates:
        return None
    # Deterministic tie-break: nearest line then stable vuln_id order.
    return sorted(candidates, key=lambda v: (abs(v.line - predicted_line), v.vuln_id))[0]


def _related_types(vuln_type: VulnerabilityType) -> set[VulnerabilityType]:
    related: set[VulnerabilityType] = set()
    for group in _RELATED_VULN_GROUPS:
        if vuln_type in group:
            related.update(group)
    related.discard(vuln_type)
    return related


def _find_related_vulnerability(
    *,
    predicted_type: VulnerabilityType,
    predicted_line: int,
    task: TaskSpec,
    addressed_ids: set[str],
) -> VulnerabilitySpec | None:
    related = _related_types(predicted_type)
    if not related:
        return None

    candidates = [
        v for v in _unresolved_vulnerabilities(task, addressed_ids) if v.type in related
    ]
    if not candidates:
        return None
    return sorted(candidates, key=lambda v: (abs(v.line - predicted_line), v.vuln_id))[0]


def _explanation_score(explanation: str, expected_vuln: VulnerabilityType) -> float:
    text = _normalize_text(explanation)
    if not text:
        return 0.0

    if len(text) < 20:
        return 0.03

    hits = _count_keyword_hits(text, _VULN_KEYWORDS.get(expected_vuln, set()))
    causality = _causality_hits(text)

    score = 0.0
    if hits >= 4:
        score += 0.14
    elif hits == 3:
        score += 0.11
    elif hits == 2:
        score += 0.08
    elif hits == 1:
        score += 0.05
    else:
        score += 0.02

    if causality >= 3:
        score += 0.06
    elif causality >= 1:
        score += 0.04

    return min(0.2, score)


def _fix_score(fix: str, vulnerability: VulnerabilitySpec) -> float:
    text = _normalize_text(fix)
    if not text:
        return 0.0

    if len(text) < 20:
        return 0.03

    expected_tokens = _tokenize(" ".join(vulnerability.accepted_fixes))
    vuln_tokens = _VULN_KEYWORDS.get(vulnerability.type, set())
    secure_pattern_tokens = {
        "parameterized",
        "allowlist",
        "validate",
        "json",
        "schema",
        "argon2",
        "bcrypt",
        "secret",
        "manager",
        "state",
        "origin",
        "tool",
        "sandbox",
    }
    candidate_tokens = _tokenize(text)

    overlap_expected = len(candidate_tokens.intersection(expected_tokens))
    overlap_vuln = len(candidate_tokens.intersection(vuln_tokens))
    secure_hits = len(candidate_tokens.intersection(secure_pattern_tokens))

    score = 0.0
    if overlap_expected >= 4 or (overlap_expected >= 2 and overlap_vuln >= 2):
        score += 0.14
    elif overlap_expected >= 3 or overlap_vuln >= 3:
        score += 0.11
    elif overlap_expected >= 2 or overlap_vuln >= 2:
        score += 0.08
    elif overlap_expected >= 1 or overlap_vuln >= 1:
        score += 0.05
    else:
        score += 0.02

    if secure_hits >= 2:
        score += 0.06
    elif secure_hits >= 1:
        score += 0.04

    return min(0.2, score)


def _line_score(predicted_line: int, expected_line: int) -> float:
    if predicted_line == expected_line:
        return 0.15
    if abs(predicted_line - expected_line) == 1:
        return 0.1
    if abs(predicted_line - expected_line) == 2:
        return 0.05
    return 0.0


def _format_score(action: Action) -> float:
    explanation_text = _normalize_text(action.explanation)
    fix_text = _normalize_text(action.fix)

    if len(explanation_text) >= 25 and len(fix_text) >= 25:
        return 0.1
    if len(explanation_text) >= 15 and len(fix_text) >= 15:
        return 0.07
    if explanation_text and fix_text:
        return 0.04
    return 0.0


def _irrelevant_penalty(action: Action, vuln_correct: bool) -> float:
    explanation_text = _normalize_text(action.explanation)
    fix_text = _normalize_text(action.fix)

    if not explanation_text and not fix_text:
        return -0.2

    low_signal = (len(explanation_text) < 10) and (len(fix_text) < 10)
    if low_signal and not vuln_correct:
        return -0.15
    if low_signal:
        return -0.1
    return 0.0


def _repeat_incorrect_decay(attempt_index: int, vulnerability_correct: bool) -> float:
    if vulnerability_correct:
        return 0.0
    if attempt_index <= 1:
        return 0.0
    return -min(0.15, 0.05 * (attempt_index - 1))


def _missing_critical_penalty(
    unresolved: Iterable[VulnerabilitySpec],
    matched: VulnerabilitySpec | None,
) -> float:
    unresolved_list = list(unresolved)
    has_critical_unresolved = any(v.severity == Severity.CRITICAL for v in unresolved_list)
    if not has_critical_unresolved:
        return 0.0
    if matched is None:
        return -0.05
    if matched.severity in {Severity.LOW, Severity.MEDIUM}:
        return -0.04
    return 0.0


def grade_action(
    action: Action,
    task: TaskSpec,
    *,
    addressed_ids: set[str] | None = None,
    attempt_index: int = 1,
    profile_overrides: dict[Difficulty, dict[str, float]] | None = None,
    strict_mode: bool = False,
) -> GradeResult:
    """
    Grade a single action deterministically with weighted components.

    Weighted components:
    - vulnerability correctness: 0.35
    - location accuracy: 0.15
    - explanation quality: 0.20
    - fix validity: 0.20
    - format adherence: 0.10

    Penalties include hallucination, irrelevance, repeated incorrect attempts,
    and missing critical issues in multi-vulnerability tasks.
    """

    addressed_ids = addressed_ids or set()
    profile = _merged_difficulty_profile(task.difficulty, profile_overrides)
    strict_partial_factor = 0.78
    if strict_mode:
        profile = {
            **profile,
            # Slightly emphasize core correctness while reducing easy over-credit.
            "vulnerability_positive": profile["vulnerability_positive"] * 1.02,
            "line_positive": profile["line_positive"] * 0.95,
            "explanation_positive": profile["explanation_positive"] * 0.9,
            "fix_positive": profile["fix_positive"] * 0.9,
            "format_positive": profile["format_positive"] * 0.85,
            "wrong_vulnerability_penalty": profile["wrong_vulnerability_penalty"] * 1.2,
            "irrelevant_penalty": profile["irrelevant_penalty"] * 1.35,
            "repeat_decay": profile["repeat_decay"] * 1.3,
            "critical_penalty": profile["critical_penalty"] * 1.35,
        }
    unresolved = _unresolved_vulnerabilities(task, addressed_ids)
    predicted_type = _resolve_predicted_type(action)
    exact_match = _find_matching_vulnerability(
        predicted_type=predicted_type,
        predicted_line=action.line_number,
        task=task,
        addressed_ids=addressed_ids,
    )
    related_match = None
    if exact_match is None:
        related_match = _find_related_vulnerability(
            predicted_type=predicted_type,
            predicted_line=action.line_number,
            task=task,
            addressed_ids=addressed_ids,
        )

    matched = exact_match or related_match
    match_quality = "exact" if exact_match is not None else "related" if related_match else "none"

    vuln_correct = exact_match is not None

    no_vuln_action = (
        action.action_type == ActionType.NO_VULNERABILITY
        or action.vulnerability_type == VulnerabilityType.NONE
    )
    if no_vuln_action:
        # Give weak agents an uncertainty-safe, small non-zero signal.
        if unresolved:
            vulnerability_component = 0.06 if strict_mode else 0.08
        else:
            vulnerability_component = 0.2
        vulnerability_component *= profile["vulnerability_positive"]
    elif match_quality == "related":
        vulnerability_component = 0.2 * profile["vulnerability_positive"]
    else:
        vulnerability_component = (
            0.35 * profile["vulnerability_positive"]
            if vuln_correct
            else -0.25 * profile["wrong_vulnerability_penalty"]
        )

    if matched is not None:
        line_multiplier = 1.0 if match_quality == "exact" else 0.65
        quality_multiplier = 1.0 if match_quality == "exact" else 0.7
        line_component = (
            _line_score(action.line_number, matched.line)
            * profile["line_positive"]
            * line_multiplier
        )
        explanation_component = (
            _explanation_score(action.explanation, matched.type) * profile["explanation_positive"]
        )
        fix_component = _fix_score(action.fix, matched) * profile["fix_positive"]
        severity_multiplier = _SEVERITY_WEIGHT[matched.severity]
        explanation_component = min(0.25, explanation_component * severity_multiplier * quality_multiplier)
        fix_component = min(0.25, fix_component * severity_multiplier * quality_multiplier)

        if strict_mode:
            # In strict mode, partial/approximate evidence should contribute less.
            if match_quality == "related":
                line_component *= strict_partial_factor
                explanation_component *= strict_partial_factor
                fix_component *= strict_partial_factor

            if action.line_number != matched.line:
                line_component *= strict_partial_factor

            if explanation_component < 0.12:
                explanation_component *= 0.8

            if fix_component < 0.12:
                fix_component *= 0.85
    else:
        line_component = 0.0
        explanation_component = 0.0
        fix_component = 0.0

    format_component = _format_score(action) * profile["format_positive"]
    irrelevant_component = _irrelevant_penalty(action, vuln_correct) * profile["irrelevant_penalty"]
    repeated_decay = _repeat_incorrect_decay(attempt_index, vuln_correct) * profile["repeat_decay"]
    critical_penalty = (
        _missing_critical_penalty(unresolved, matched) * profile["critical_penalty"]
    )

    raw_reward = (
        vulnerability_component
        + line_component
        + explanation_component
        + fix_component
        + format_component
        + irrelevant_component
        + repeated_decay
        + critical_penalty
    )

    if strict_mode:
        # Global calibration keeps strict mode slightly harsher at episode level,
        # especially when multi-step accumulation would otherwise saturate at 1.0.
        raw_reward *= 0.9

    reward = max(0.0, min(1.0, raw_reward))

    newly_addressed = False
    if exact_match is not None:
        # Require both issue understanding and actionable remediation for completion credit.
        if strict_mode:
            newly_addressed = (
                line_component >= 0.1
                and explanation_component >= 0.1
                and fix_component >= 0.1
            )
        else:
            newly_addressed = (
                line_component >= 0.1
                and explanation_component >= 0.08
                and fix_component >= 0.08
            )

    breakdown = {
        "strict_mode": 1.0 if strict_mode else 0.0,
        "match_quality": 1.0 if match_quality == "exact" else 0.5 if match_quality == "related" else 0.0,
        "vulnerability": round(vulnerability_component, 4),
        "line": round(line_component, 4),
        "explanation": round(explanation_component, 4),
        "fix": round(fix_component, 4),
        "format": round(format_component, 4),
        "irrelevant_penalty": round(irrelevant_component, 4),
        "repeat_decay": round(repeated_decay, 4),
        "missing_critical_penalty": round(critical_penalty, 4),
        "raw_total": round(raw_reward, 4),
        "final_reward": round(reward, 4),
    }

    done_reason = "action_graded"
    return GradeResult(
        reward=reward,
        breakdown=breakdown,
        done_reason=done_reason,
        matched_vulnerability_id=matched.vuln_id if matched else None,
        newly_addressed=newly_addressed,
    )
