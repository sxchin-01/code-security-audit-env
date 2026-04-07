from __future__ import annotations

import json
import os
import re
from typing import Any

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency
    load_dotenv = None
import httpx
from openai import OpenAI
from pydantic import ValidationError

from app.env import CodeSecurityAuditEnv, EnvConfig
from app.models import Action, ActionType, Observation, VulnerabilityType
from app.tasks import get_all_tasks


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    return normalized in {"1", "true", "yes", "y", "on"}


SYSTEM_PROMPT = (
    "You are a security code auditor agent in an RL benchmark. "
    "Given one code snippet, identify the vulnerability, line number, explanation, and fix. "
    "Return ONLY valid JSON matching this schema: "
    "{"
    "\"action_type\": \"report_vulnerability\" or \"suggest_fix\" or \"no_vulnerability\", "
    "\"vulnerability_type\": one of [\"SQL Injection\",\"XSS\",\"Hardcoded Secret\"," 
    "\"Improper Validation\",\"Weak Hashing\",\"Command Injection\",\"Path Traversal\"," 
    "\"Broken Authentication\",\"Missing Rate Limiting\",\"Sensitive Data Exposure\","
    "\"Insecure Debug Configuration\"," 
    "\"Insecure Deserialization\",\"SSRF\",\"API Key Leakage\","
    "\"CORS Misconfiguration\",\"OAuth Redirect Misvalidation\","
    "\"Prompt Injection\",\"AI Generated Insecure Code\",\"None\"], "
    "\"line_number\": integer >= 1, "
    "\"explanation\": string, "
    "\"fix\": string"
    "}."
)


def _extract_text_from_content(content: Any) -> str:
    """Extract text from chat content that may be a string or structured list."""

    if isinstance(content, str):
        return content.strip()

    if isinstance(content, list):
        text_parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                if item.strip():
                    text_parts.append(item.strip())
                continue
            if not isinstance(item, dict):
                continue

            # Common shapes:
            # {"type": "text", "text": "..."}
            # {"type": "output_text", "text": "..."}
            # {"content": "..."}
            # {"content": [{"text": "..."}]}
            text_value = item.get("text")
            if isinstance(text_value, str) and text_value.strip():
                text_parts.append(text_value.strip())

            content_value = item.get("content")
            nested = _extract_text_from_content(content_value)
            if nested:
                text_parts.append(nested)

        return "\n".join([part for part in text_parts if part]).strip()

    if isinstance(content, dict):
        # Try known direct keys first, then recurse into nested "content".
        for key in ("text", "output_text", "generated_text"):
            value = content.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return _extract_text_from_content(content.get("content"))

    return ""


def _call_hf_inference(*, api_base: str, api_key: str, model_name: str, prompt: str) -> str:
    """Call OpenAI-compatible chat completion API using environment-driven settings."""

    client = OpenAI(
        base_url=api_base,
        api_key=api_key,
    )

    try:
        completion = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "user", "content": prompt},
            ],
            temperature=0.0,
            max_tokens=280,
            stream=False,
        )
    except Exception as exc:
        raise RuntimeError(f"Inference request failed: {exc}") from exc

    generated_text = completion.choices[0].message.content or ""
    return generated_text


def _build_user_prompt(observation: Observation) -> str:
    history = observation.history or []
    history_text = "\n".join(
        [
            f"- action={item.action_type.value}, vuln={item.vulnerability_type.value}, "
            f"line={item.line_number}, reward={item.reward:.2f}"
            for item in history
        ]
    )
    if not history_text:
        history_text = "- none"

    return (
        f"Task ID: {observation.task_id}\n"
        f"Difficulty: {observation.difficulty.value}\n"
        f"Language: {observation.language}\n"
        f"Context: {observation.context}\n"
        f"Code:\n{observation.code}\n\n"
        f"Previous actions:\n{history_text}\n\n"
        "Respond with JSON only."
    )


def _fallback_action() -> Action:
    """Safe fallback action when model output is malformed."""

    return Action(
        action_type=ActionType.REPORT_VULNERABILITY,
        vulnerability_type=VulnerabilityType.NONE,
        line_number=1,
        explanation="Unable to parse model response.",
        fix="Provide a concrete vulnerability finding and remediation.",
    )


def _coerce_json_object(content: str) -> dict[str, Any] | None:
    """Try to recover a JSON object from model output robustly."""

    content = content.strip()
    if not content:
        return None

    # Direct JSON parse first.
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # Attempt to extract the first JSON object block if wrapped in extra text.
    start = content.find("{")
    end = content.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    try:
        parsed = json.loads(content[start : end + 1])
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        return None

    return None


def _line_number_from_text(text: str) -> int:
    """Extract first plausible line number from free-form model text."""

    matches = re.findall(r"(?:line\s*[:#-]?\s*)(\d{1,3})", text, flags=re.IGNORECASE)
    if matches:
        return max(1, int(matches[0]))

    standalone = re.findall(r"\b(\d{1,3})\b", text)
    if standalone:
        return max(1, int(standalone[0]))

    return 1


def _vulnerability_from_text(text: str) -> VulnerabilityType:
    """Map free-form text to the canonical vulnerability enum."""

    normalized = text.lower()
    mapping: list[tuple[str, VulnerabilityType]] = [
        ("sql injection", VulnerabilityType.SQL_INJECTION),
        ("sqli", VulnerabilityType.SQL_INJECTION),
        ("xss", VulnerabilityType.XSS),
        ("cross-site scripting", VulnerabilityType.XSS),
        ("hardcoded secret", VulnerabilityType.HARDCODED_SECRET),
        ("hardcoded password", VulnerabilityType.HARDCODED_SECRET),
        ("api key leakage", VulnerabilityType.API_KEY_LEAKAGE),
        ("credential leak", VulnerabilityType.API_KEY_LEAKAGE),
        ("cors misconfiguration", VulnerabilityType.CORS_MISCONFIGURATION),
        ("wildcard origin", VulnerabilityType.CORS_MISCONFIGURATION),
        ("oauth redirect", VulnerabilityType.OAUTH_REDIRECT_MISVALIDATION),
        ("open redirect", VulnerabilityType.OAUTH_REDIRECT_MISVALIDATION),
        ("prompt injection", VulnerabilityType.PROMPT_INJECTION),
        ("instruction injection", VulnerabilityType.PROMPT_INJECTION),
        ("ai generated insecure code", VulnerabilityType.AI_GENERATED_INSECURE_CODE),
        ("unsafe llm output", VulnerabilityType.AI_GENERATED_INSECURE_CODE),
        ("improper validation", VulnerabilityType.IMPROPER_VALIDATION),
        ("input validation", VulnerabilityType.IMPROPER_VALIDATION),
        ("weak hashing", VulnerabilityType.WEAK_HASHING),
        ("md5", VulnerabilityType.WEAK_HASHING),
        ("command injection", VulnerabilityType.COMMAND_INJECTION),
        ("os command injection", VulnerabilityType.COMMAND_INJECTION),
        ("shell injection", VulnerabilityType.COMMAND_INJECTION),
        ("path traversal", VulnerabilityType.PATH_TRAVERSAL),
        ("directory traversal", VulnerabilityType.PATH_TRAVERSAL),
        ("file traversal", VulnerabilityType.PATH_TRAVERSAL),
        ("broken auth", VulnerabilityType.BROKEN_AUTHENTICATION),
        ("authentication flaw", VulnerabilityType.BROKEN_AUTHENTICATION),
        ("weak authentication", VulnerabilityType.BROKEN_AUTHENTICATION),
        ("no rate limiting", VulnerabilityType.RATE_LIMITING),
        ("missing rate limiting", VulnerabilityType.RATE_LIMITING),
        ("brute force vulnerability", VulnerabilityType.RATE_LIMITING),
        ("sensitive data exposure", VulnerabilityType.SENSITIVE_DATA_EXPOSURE),
        ("data leak", VulnerabilityType.SENSITIVE_DATA_EXPOSURE),
        ("logging secrets", VulnerabilityType.SENSITIVE_DATA_EXPOSURE),
        ("insecure debug", VulnerabilityType.DEBUG_CONFIGURATION),
        ("debug mode enabled", VulnerabilityType.DEBUG_CONFIGURATION),
        ("debug=true in production", VulnerabilityType.DEBUG_CONFIGURATION),
        ("insecure deserialization", VulnerabilityType.INSECURE_DESERIALIZATION),
        ("pickle", VulnerabilityType.INSECURE_DESERIALIZATION),
        ("ssrf", VulnerabilityType.SSRF),
        ("server-side request forgery", VulnerabilityType.SSRF),
    ]

    for key, vuln in mapping:
        if key in normalized:
            return vuln
    return VulnerabilityType.NONE


def _fallback_action_from_text(text: str) -> Action:
    """Build best-effort structured action from non-JSON model output."""

    vuln = _vulnerability_from_text(text)
    line_number = _line_number_from_text(text)

    action_type = ActionType.SUGGEST_FIX if "fix" in text.lower() else ActionType.REPORT_VULNERABILITY
    explanation = text.strip()[:700] or "Model returned non-JSON analysis text."
    fix = "Use secure coding best practices and apply targeted remediation for the identified vulnerability."

    # Try to extract a compact fix phrase when present.
    fix_match = re.search(r"(?:fix|remediation|mitigation)\s*[:\-]\s*(.+)", text, flags=re.IGNORECASE)
    if fix_match:
        fix_candidate = fix_match.group(1).strip()
        if fix_candidate:
            fix = fix_candidate[:500]

    return Action(
        action_type=action_type,
        vulnerability_type=vuln,
        line_number=max(1, line_number),
        explanation=explanation,
        fix=fix,
    )


def _mock_action(env: CodeSecurityAuditEnv, step_idx: int) -> Action:
    """Deterministic local policy used when API env config is missing."""

    st = env.state()
    task = st.current_task
    if task is None:
        return _fallback_action()

    remaining = set(st.remaining_vulnerabilities)
    target = None
    for vuln in task.vulnerabilities:
        if vuln.vuln_id in remaining:
            target = vuln
            break
    if target is None:
        target = task.vulnerabilities[0]

    if task.task_id == "medium_cors_misconfig_01" and step_idx == 1:
        return Action(
            action_type=ActionType.NO_VULNERABILITY,
            vulnerability_type=VulnerabilityType.NONE,
            line_number=1,
            explanation="Unsure. Need more evidence.",
            fix="",
        )

    return Action(
        action_type=(
            ActionType.SUGGEST_FIX if step_idx > 1 else ActionType.REPORT_VULNERABILITY
        ),
        vulnerability_type=VulnerabilityType(target.type.value),
        line_number=target.line,
        explanation=(
            f"User-controlled or unsafe handling enables {target.type.value}. "
            "This can allow attacker abuse."
        ),
        fix=target.accepted_fixes[0] if target.accepted_fixes else "Apply secure remediation.",
    )


def _action_from_llm(
    *,
    api_base: str,
    model_name: str,
    api_key: str,
    observation: Observation,
) -> Action:
    user_prompt = _build_user_prompt(observation)

    full_prompt = f"{SYSTEM_PROMPT}\n\n{user_prompt}"
    generated = _call_hf_inference(
        api_base=api_base,
        model_name=model_name,
        api_key=api_key,
        prompt=full_prompt,
    )

    payload = _coerce_json_object(generated)
    if payload is None:
        return _fallback_action_from_text(generated)

    try:
        return Action.model_validate(payload)
    except ValidationError:
        return _fallback_action_from_text(generated)


def run_baseline(*, strict_mode: bool = False) -> None:
    """Run one deterministic pass over the full task list and print scores."""

    # Environment-driven API configuration.
    api_base = os.environ.get("API_BASE_URL")
    model_name = (
        os.environ.get("MODEL_NAME")
        or os.environ.get("OPENAI_MODEL")
        or "gpt-4o-mini"
    )
    api_key = os.environ.get("API_KEY") or os.environ.get("HF_TOKEN")

    api_enabled = bool(api_base and api_key)
    if api_key:
        lowered = api_key.lower()
        if "your_" in lowered or "replace" in lowered or "token_here" in lowered:
            api_enabled = False

    env = CodeSecurityAuditEnv(config=EnvConfig(strict_mode=strict_mode))

    task_count = len(get_all_tasks())
    final_scores: list[float] = []

    mode = "api" if api_enabled else "mock"
    display_model = model_name if api_enabled else "deterministic-mock"
    print(
        f"Running baseline on {task_count} tasks with model={display_model} "
        f"strict_mode={strict_mode} mode={mode}"
    )

    for idx in range(task_count):
        observation = env.reset()
        done = False
        episode_reward = 0.0
        step_index = 0

        print(f"[START] task={observation.task_id}", flush=True)

        while not done:
            step_index += 1
            if api_enabled and api_base and api_key:
                try:
                    action = _action_from_llm(
                        api_base=api_base,
                        model_name=model_name,
                        api_key=api_key,
                        observation=observation,
                    )
                except RuntimeError as exc:
                    raise RuntimeError(f"LLM inference failed: {exc}") from exc
            else:
                action = _mock_action(env, step_index)
            observation, reward, done, info = env.step(action)
            episode_reward += reward

            print(
                f"[STEP] task={observation.task_id} step={step_index} "
                f"reward={reward:.4f}",
                flush=True,
            )

            print(
                f"[task {idx + 1}/{task_count}] step={step_index} "
                f"reward={reward:.4f} done={done} reason={info.get('done_reason')}"
            )

        # Primary metric: average per-step reward (prevents multi-step saturation).
        num_steps = max(step_index, 1)
        final_task_score = episode_reward / num_steps
        final_task_score = max(0.0, min(1.0, final_task_score))
        final_scores.append(final_task_score)

        print(
            f"[END] task={observation.task_id} score={final_task_score:.4f} "
            f"steps={num_steps}",
            flush=True,
        )

        print(
            f"[task {idx + 1}/{task_count}] task_id={observation.task_id} "
            f"difficulty={observation.difficulty.value} "
            f"final_score={final_task_score:.4f}"
        )

    average_final_score = sum(final_scores) / len(final_scores) if final_scores else 0.0

    print("\n=== Summary ===")
    for i, final_score in enumerate(final_scores, start=1):
        print(f"Task {i}:")
        print(f"  final_score: {final_score:.4f}")
    print(f"Average final_score: {average_final_score:.4f}")


def main() -> None:
    if load_dotenv is not None:
        load_dotenv()  # Load from .env file when dotenv is installed.
    strict_mode = _env_bool("STRICT_MODE", default=False)
    try:
        run_baseline(strict_mode=strict_mode)
    except RuntimeError as exc:
        print(f"ERROR: {exc}")


if __name__ == "__main__":
    main()
