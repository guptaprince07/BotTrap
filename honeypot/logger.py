"""Builds the event dict (contract 5.4) from a Flask request and stores it.

The honeypot never executes, evaluates or reflects input. It only logs.
"""
import hashlib
import json
import sys

MAX_BODY = 4096      # chars stored for body
MAX_HEADERS = 4096   # chars stored for headers JSON

# shared.db is owned by Vidanshi. If it is not importable yet (local solo
# testing), fall back to printing the event so the honeypot still runs.
try:
    from shared.db import insert_event
except Exception as exc:  # pragma: no cover
    print(f"[honeypot] shared.db unavailable ({exc}); events will only be printed", file=sys.stderr)

    def insert_event(event: dict) -> int:
        print("[honeypot:event]", json.dumps(event)[:500], file=sys.stderr)
        return -1


def get_client_ip(request) -> str:
    """First value of X-Forwarded-For (Render proxy / simulate.py), else remote_addr."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first[:64]
    return (request.remote_addr or "unknown")[:64]


def _read_body(request) -> str:
    try:
        raw = request.get_data(cache=True)  # size already capped by MAX_CONTENT_LENGTH
        return raw.decode("utf-8", errors="replace")[:MAX_BODY]
    except Exception:
        return ""  # e.g. 413 too large: skip the body, still log the request


def build_event(request) -> dict:
    body = _read_body(request)
    query = request.query_string.decode("utf-8", errors="replace")
    path = request.path
    headers = json.dumps({k: v for k, v in request.headers.items()})[:MAX_HEADERS]
    user_agent = request.headers.get("User-Agent", "")[:512]
    digest_src = f"{request.method}{path}{query}{body}"
    return {
        "ip": get_client_ip(request),
        "method": request.method[:10],
        "path": path[:512],
        "query": query[:2048],
        "headers": headers,
        "body": body,
        "user_agent": user_agent,
        "payload_hash": hashlib.sha256(digest_src.encode("utf-8", errors="replace")).hexdigest(),
    }


def log_request(request) -> None:
    """Log one request. Never raises: the honeypot must keep answering."""
    if request.path == "/health":
        return
    try:
        insert_event(build_event(request))
    except Exception as exc:
        print(f"[honeypot] failed to log event: {exc}", file=sys.stderr)
