from __future__ import annotations

import json
import os
import re
from typing import Any

from dotenv import load_dotenv
import httpx
from pydantic import ValidationError

from app.env import CodeSecurityAuditEnv, EnvConfig
from app.models import Action, ActionType, Observation, VulnerabilityType
from app.tasks import get_all_tasks


SUPPORTED_PROVIDERS = {"hf", "gemini"}


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
    "\"Improper Validation\",\"Weak Hashing\",\"Path Traversal\"," 
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


def _call_hf_inference(*, api_key: str, model: str, prompt: str) -> str:
    """Call Hugging Face Inference API and return generated text."""

    url = "https://router.huggingface.co/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
        "max_tokens": 280,
        "stream": False,
    }

    with httpx.Client(timeout=90.0) as client:
        response = client.post(url, headers=headers, json=payload)

    if response.status_code in (401, 403):
        raise RuntimeError(
            "Hugging Face authentication failed. Check HF_API_KEY token permissions."
        )
    if response.status_code == 429:
        raise RuntimeError(
            "Hugging Face rate limit/quota reached (429). Retry later or change model/token."
        )
    if response.status_code >= 400:
        raise RuntimeError(
            f"Hugging Face inference request failed ({response.status_code}): {response.text}"
        )

    data: Any = response.json()

    # OpenAI-compatible chat completion response from Hugging Face router.
    if isinstance(data, dict):
        if "error" in data:
            raise RuntimeError(f"Hugging Face API error: {data['error']}")
        choices = data.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            choice0 = choices[0]
            message = choice0.get("message") or choice0.get("delta")
            if isinstance(message, dict):
                generated_text = _extract_text_from_content(message.get("content"))
                if generated_text:
                    return generated_text

                # Some reasoning-capable models place output here.
                reasoning_text = _extract_text_from_content(message.get("reasoning_content"))
                if reasoning_text:
                    return reasoning_text

                # Some providers use "reasoning" instead of "reasoning_content".
                reasoning_text = _extract_text_from_content(message.get("reasoning"))
                if reasoning_text:
                    return reasoning_text

            # Some providers may put text directly on the choice.
            generated_text = _extract_text_from_content(choice0.get("text"))
            if generated_text:
                return generated_text

        # Fallback keys used by several providers.
        for key in ("generated_text", "output_text", "text", "completion", "response"):
            generated_text = _extract_text_from_content(data.get(key))
            if generated_text:
                return generated_text

        # Responses-style payloads may include output arrays.
        output_text = _extract_text_from_content(data.get("output"))
        if output_text:
            return output_text

    # Some backends return list payloads; scan for text-bearing entries.
    if isinstance(data, list):
        list_text = _extract_text_from_content(data)
        if list_text:
            return list_text

    debug_preview = json.dumps(data, ensure_ascii=True)[:800]
    if os.getenv("HF_DEBUG_RESPONSE", "").strip() == "1":
        print(f"HF DEBUG response preview: {debug_preview}")
    raise RuntimeError(
        "Unexpected Hugging Face response format; no generated text found. "
        "Set HF_DEBUG_RESPONSE=1 to print response preview."
    )


def _call_gemini_inference(*, api_key: str, model: str, prompt: str) -> str:
    """Call Gemini API and return generated text."""

    def _discover_supported_model(client: httpx.Client) -> str | None:
        list_url = "https://generativelanguage.googleapis.com/v1beta/models"
        list_resp = client.get(list_url, params={"key": api_key})
        if list_resp.status_code >= 400:
            return None

        data: Any = list_resp.json()
        models = data.get("models") if isinstance(data, dict) else None
        if not isinstance(models, list):
            return None

        candidates: list[str] = []
        for item in models:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            methods = item.get("supportedGenerationMethods", [])
            if not isinstance(name, str) or not isinstance(methods, list):
                continue
            if "generateContent" not in methods:
                continue
            if not name.startswith("models/"):
                continue
            candidates.append(name.removeprefix("models/"))

        if not candidates:
            return None

        preferred_order = [
            "gemini-2.5-flash",
            "gemini-2.0-flash",
            "gemini-1.5-flash",
            "gemini-1.5-pro",
        ]
        for preferred in preferred_order:
            for candidate in candidates:
                if preferred in candidate:
                    return candidate

        return sorted(candidates)[0]

    def _post_generate_content(client: httpx.Client, target_model: str) -> httpx.Response:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{target_model}:generateContent"
        )
        params = {"key": api_key}
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.0,
                "maxOutputTokens": 280,
            },
        }
        return client.post(url, params=params, json=payload)

    fallback_models: list[str] = []
    if model == "gemini-1.5-flash":
        fallback_models = ["gemini-2.0-flash", "gemini-1.5-flash-latest", "gemini-1.5-flash-002"]

    with httpx.Client(timeout=90.0) as client:
        response = _post_generate_content(client, model)
        if response.status_code == 404 and fallback_models:
            for fallback in fallback_models:
                response = _post_generate_content(client, fallback)
                if response.status_code < 400:
                    break
        if response.status_code == 404:
            discovered = _discover_supported_model(client)
            if discovered and discovered not in {model, *fallback_models}:
                response = _post_generate_content(client, discovered)

    if response.status_code in (401, 403):
        raise RuntimeError("Gemini authentication failed. Check GEMINI_API_KEY.")
    if response.status_code == 429:
        raise RuntimeError("Gemini rate limit reached (429). Retry later.")
    if response.status_code == 402:
        raise RuntimeError("Gemini billing/quota limit reached (402).")
    if response.status_code >= 400:
        raise RuntimeError(f"Gemini request failed ({response.status_code}): {response.text}")

    data: Any = response.json()

    candidates = data.get("candidates") if isinstance(data, dict) else None
    if isinstance(candidates, list) and candidates:
        candidate0 = candidates[0]
        if isinstance(candidate0, dict):
            content = candidate0.get("content")
            if isinstance(content, dict):
                parts = content.get("parts")
                generated_text = _extract_text_from_content(parts)
                if generated_text:
                    return generated_text

            # Some Gemini responses include direct text-like fields.
            for key in ("text", "output", "response"):
                generated_text = _extract_text_from_content(candidate0.get(key))
                if generated_text:
                    return generated_text

    debug_preview = json.dumps(data, ensure_ascii=True)[:800]
    if os.getenv("GEMINI_DEBUG_RESPONSE", "").strip() == "1":
        print(f"GEMINI DEBUG response preview: {debug_preview}")
    raise RuntimeError(
        "Unexpected Gemini response format; no generated text found. "
        "Set GEMINI_DEBUG_RESPONSE=1 to print response preview."
    )


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
        ("path traversal", VulnerabilityType.PATH_TRAVERSAL),
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


def _action_from_llm(
    *,
    provider: str,
    api_key: str,
    model: str,
    observation: Observation,
) -> Action:
    user_prompt = _build_user_prompt(observation)

    full_prompt = f"{SYSTEM_PROMPT}\n\n{user_prompt}"
    if provider == "hf":
        generated = _call_hf_inference(api_key=api_key, model=model, prompt=full_prompt)
    elif provider == "gemini":
        generated = _call_gemini_inference(api_key=api_key, model=model, prompt=full_prompt)
    else:
        raise RuntimeError(f"Unsupported provider: {provider}")

    payload = _coerce_json_object(generated)
    if payload is None:
        return _fallback_action_from_text(generated)

    try:
        return Action.model_validate(payload)
    except ValidationError:
        return _fallback_action_from_text(generated)


def run_baseline(*, provider: str, model: str, strict_mode: bool = False) -> None:
    """Run one deterministic pass over the full task list and print scores."""

    provider = provider.lower().strip()
    if provider not in SUPPORTED_PROVIDERS:
        raise RuntimeError(
            f"Unsupported LLM_PROVIDER '{provider}'. Use one of: {sorted(SUPPORTED_PROVIDERS)}"
        )

    if provider == "hf":
        api_key = os.getenv("HF_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("HF_API_KEY is required when LLM_PROVIDER=hf")
        if "your_" in api_key.lower() or "replace" in api_key.lower() or "hf-your" in api_key.lower():
            raise RuntimeError("HF_API_KEY looks like a placeholder. Set a real token and try again.")
    else:
        api_key = os.getenv("GEMINI_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY is required when LLM_PROVIDER=gemini")
        if "your_" in api_key.lower() or "replace" in api_key.lower() or "gemini" in api_key.lower():
            raise RuntimeError(
                "GEMINI_API_KEY looks like a placeholder. Set a real key and try again."
            )

    env = CodeSecurityAuditEnv(config=EnvConfig(strict_mode=strict_mode))

    task_count = len(get_all_tasks())
    final_scores: list[float] = []

    print(
        f"Running baseline on {task_count} tasks with provider={provider} "
        f"model={model} strict_mode={strict_mode}"
    )

    for idx in range(task_count):
        observation = env.reset()
        done = False
        episode_reward = 0.0
        step_index = 0

        while not done:
            step_index += 1
            try:
                action = _action_from_llm(
                    provider=provider,
                    api_key=api_key,
                    model=model,
                    observation=observation,
                )
            except RuntimeError as exc:
                raise RuntimeError(f"LLM inference failed: {exc}") from exc
            observation, reward, done, info = env.step(action)
            episode_reward += reward

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
    load_dotenv()  # Load from .env file
    provider = os.getenv("LLM_PROVIDER", "hf").strip().lower()
    strict_mode = _env_bool("STRICT_MODE", default=False)
    model = (
        os.getenv("HF_MODEL", "deepseek-ai/DeepSeek-R1:fastest")
        if provider == "hf"
        else os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    )
    try:
        run_baseline(provider=provider, model=model, strict_mode=strict_mode)
    except RuntimeError as exc:
        print(f"ERROR: {exc}")


if __name__ == "__main__":
    main()
