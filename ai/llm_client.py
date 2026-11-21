"""LLM client and classification skeleton."""
"""LLM client supporting Groq and Google Gemini free tiers via requests."""

from collections import deque
import json
import os
import re
import threading
import time
import requests
from dotenv import load_dotenv

from ai.prompts import (
    build_classification_system_prompt,
    build_classification_user_prompt,
    build_report_prompts,
    load_mitre_map,
)

load_dotenv()

ALLOWED_ATTACK_TYPES = {
    "SQL Injection",
    "XSS",
    "Brute Force",
    "Credential Stuffing",
    "Path Traversal",
    "Command Injection",
    "Vulnerability Scan",
    "Recon",
    "Sensitive File Probe",
    "Web Shell Upload",
    "Other",
}

ALLOWED_SEVERITIES = {"Low", "Medium", "High", "Critical"}

DEFAULT_RECOMMENDED_RULE = "Rate-limit source IP at reverse proxy"

# Thread-safe sliding window for rate limiting LLM calls per minute
_rate_lock = threading.Lock()
_call_timestamps: deque[float] = deque()


def _fallback_classification(reason: str = "Unclassified anomalous HTTP probe.") -> dict:
    """Return a contract-compliant fallback classification dict."""
    mitre_map = load_mitre_map()
    default_mitre_id = "T1595" if "T1595" in mitre_map else next(iter(mitre_map))
    return {
        "attack_type": "Other",
        "severity": "Low",
        "mitre_id": default_mitre_id,
        "mitre_name": mitre_map.get(default_mitre_id, "Active Scanning"),
        "likely_tool": "unknown",
        "explanation": reason[:200],
        "recommended_rule": DEFAULT_RECOMMENDED_RULE,
        "source": "fallback",
    }


def _acquire_rate_limit_slot() -> bool:
    """Check if an LLM call is permitted under LLM_MAX_PER_MIN."""
    try:
        max_per_min = int(os.getenv("LLM_MAX_PER_MIN", "20"))
    except ValueError:
        max_per_min = 20

    if max_per_min <= 0:
        return False

    now = time.monotonic()
    with _rate_lock:
        while _call_timestamps and (now - _call_timestamps[0]) >= 60.0:
            _call_timestamps.popleft()
        if len(_call_timestamps) >= max_per_min:
            return False
        _call_timestamps.append(now)
        return True


def _strip_markdown_fences(raw_text: str) -> str:
    """Strip ```json ... ``` or ``` ... ``` wrappers and isolate JSON object."""
    text = raw_text.strip()
    # Remove leading/trailing markdown code fences
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text)
    text = text.strip()

    # If the model wrapped JSON with brief commentary, extract outermost {...}
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        text = text[start : end + 1]
    return text


def _call_groq(system_prompt: str, user_prompt: str, temperature: float = 0.1) -> str:
    """Call Groq OpenAI-compatible chat completions endpoint."""
    api_key = os.getenv("LLM_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("LLM_API_KEY is missing")

    model = os.getenv("LLM_MODEL", "").strip() or "llama-3.1-8b-instant"
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
        "max_tokens": 350,
    }

    resp = requests.post(url, headers=headers, json=payload, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def _call_gemini(system_prompt: str, user_prompt: str, temperature: float = 0.1) -> str:
    """Call Google Gemini generateContent REST endpoint."""
    api_key = os.getenv("LLM_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("LLM_API_KEY is missing")

    model = os.getenv("LLM_MODEL", "").strip() or "gemini-2.5-flash"
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    headers = {
        "x-goog-api-key": api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": 350,
        },
    }

    resp = requests.post(url, headers=headers, json=payload, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    return data["candidates"][0]["content"]["parts"][0]["text"]


def _invoke_provider(system_prompt: str, user_prompt: str, temperature: float = 0.1) -> str:
    """Dispatch request to configured provider with 1 retry on transient failure."""
    provider = os.getenv("LLM_PROVIDER", "groq").strip().lower()
    caller = _call_gemini if provider == "gemini" else _call_groq

    last_err = None
    for attempt in range(2):  # initial attempt + 1 retry
        try:
            return caller(system_prompt, user_prompt, temperature=temperature)
        except Exception as exc:
            last_err = exc
            if attempt == 0:
                time.sleep(0.6)
    raise last_err


def _validate_and_normalize(raw_text: str) -> dict:
    """Parse JSON response and validate against Section 5.3 & shared/mitre.json."""
    cleaned = _strip_markdown_fences(raw_text)
    parsed = json.loads(cleaned)
    if not isinstance(parsed, dict):
        raise ValueError("LLM response is not a JSON object")

    mitre_map = load_mitre_map()

    attack_type = str(parsed.get("attack_type", "")).strip()
    severity = str(parsed.get("severity", "")).strip()
    mitre_id = str(parsed.get("mitre_id", "")).strip()

    if attack_type not in ALLOWED_ATTACK_TYPES:
        raise ValueError(f"Invalid attack_type: {attack_type}")
    if severity not in ALLOWED_SEVERITIES:
        raise ValueError(f"Invalid severity: {severity}")
    if mitre_id not in mitre_map:
        raise ValueError(f"Unknown mitre_id: {mitre_id}")

    likely_tool = str(parsed.get("likely_tool") or "unknown").strip()[:64] or "unknown"
    explanation = str(parsed.get("explanation") or "Suspicious HTTP request detected.").strip()[:300]
    recommended_rule = (
        str(parsed.get("recommended_rule") or DEFAULT_RECOMMENDED_RULE).strip()[:500]
        or DEFAULT_RECOMMENDED_RULE
    )

    return {
        "attack_type": attack_type,
        "severity": severity,
        "mitre_id": mitre_id,
        "mitre_name": mitre_map[mitre_id],
        "likely_tool": likely_tool,
        "explanation": explanation,
        "recommended_rule": recommended_rule,
        "source": "llm",
    }


def classify_with_llm(event: dict) -> dict:
    """Classify an HTTP event using the configured LLM provider.

    Never raises; falls back cleanly on rate limits, API failures, or invalid JSON.
    """
    if not _acquire_rate_limit_slot():
        return _fallback_classification("LLM rate limit reached; queued as generic probe.")

    system_prompt = build_classification_system_prompt()
    user_prompt = build_classification_user_prompt(event)

    try:
        raw_response = _invoke_provider(system_prompt, user_prompt, temperature=0.1)
        return _validate_and_normalize(raw_response)
    except Exception:
        return _fallback_classification("Automated AI classification unavailable for this payload.")


def generate_report(events: list[dict]) -> str:
    """Generate a plain-English incident summary for one attacker's events."""
    if not events:
        return "No recorded events found for this IP address."

    ip = events[0].get("ip", "unknown")
    attack_types = sorted({e.get("attack_type") for e in events if e.get("attack_type")})
    severities = sorted({e.get("severity") for e in events if e.get("severity")})

    fallback_summary = (
        f"Source IP {ip} generated {len(events)} captured event(s) targeting the honeypot. "
        f"Observed categories include {', '.join(attack_types) or 'unclassified probes'} "
        f"(severities: {', '.join(severities) or 'Low'}). "
        f"Recommended action: block or rate-limit {ip} at the perimeter firewall or reverse proxy."
    )

    if not _acquire_rate_limit_slot():
        return fallback_summary

    system_prompt, user_prompt = build_report_prompts(events)
    try:
        text = _invoke_provider(system_prompt, user_prompt, temperature=0.2)
        cleaned = text.strip()
        return cleaned if cleaned else fallback_summary
    except Exception:
        return fallback_summary
VALID_TARGETS = {"path", "query", "body", "user_agent", "any"}


def _parse_rule_fields(raw_data: dict) -> tuple[str | None, str]:
    if not isinstance(raw_data, dict):
        return None, "any"

    raw_regex = raw_data.get("suggested_regex")
    suggested_regex = raw_regex.strip() if isinstance(raw_regex, str) and raw_regex.strip() else None

    raw_target = raw_data.get("regex_target")
    regex_target = raw_target.strip() if isinstance(raw_target, str) and raw_target.strip() in VALID_TARGETS else "any"

    return suggested_regex, regex_target


# Inside your existing classify(event) return dict:
# suggested_regex, regex_target = _parse_rule_fields(parsed)
# return {
#     ...,
#     "source": "llm",
#     "suggested_regex": suggested_regex,
#     "regex_target": regex_target,
# }
