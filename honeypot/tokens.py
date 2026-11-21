from shared.db import issue_honey_token, make_token

FALLBACK = {
    "api_key": "bt_live_000000000000",
    "password": "Passw0rd-Change-Me",
}


def token_for(ip: str, path: str, kind: str, user_agent: str = "") -> str:
    """Issue or retrieve a tracked honey-token; fall back to an untracked placeholder if rate-limited."""
    row = issue_honey_token(ip, path, kind, user_agent)
    return row["token"] if row else FALLBACK[kind]


__all__ = ["FALLBACK", "make_token", "token_for"]
