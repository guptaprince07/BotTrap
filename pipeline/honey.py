import json


def _stringify(val) -> str:
    if val is None:
        return ""
    if isinstance(val, (dict, list)):
        return json.dumps(val, sort_keys=True)
    return str(val)


def detect_honey_token(event: dict, tokens: dict[str, int]) -> int | None:
    """
    tokens: {token_string: token_id} from load_active_tokens().
    Returns token_id of the first honey-token found anywhere in the request, else None.
    """
    if not tokens:
        return None
    hay = " ".join(
        _stringify(event.get(k))
        for k in ("path", "query", "body", "headers", "user_agent")
    )
    for tok, tid in tokens.items():
        if tok in hay:  # plain substring, no regex
            return tid
    return None


def honey_result(event: dict, row: dict) -> dict:
    """row = dict returned by record_token_use(); row['seconds_since_issue'] is now minus created_at."""
    secs = row["seconds_since_issue"]
    diff_ip = row["issued_to_ip"] != event["ip"]
    text = (
        f"Used the fake {row['kind']} leaked at {row['issued_on_path']} "
        f"{secs}s earlier. The attacker read the leak and tried it."
    )
    if diff_ip:
        text += " (from a different IP, so the attacker's tooling is split across machines)"

    return {
        "attack_type": "Honey-Token Used",
        "severity": "Critical",
        "mitre_id": "T1078",
        "mitre_name": "Valid Accounts",
        "likely_tool": "unknown",
        "explanation": text,
        "recommended_rule": f"deny {event['ip']};   # Nginx: block this IP",
        "source": "honey_token",
    }
