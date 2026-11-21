from fastapi import Query
from shared.db import list_honey_tokens, token_stats


@app.get("/api/tokens")
def get_tokens(
    status: str | None = Query(default=None, pattern="^(issued|used)$"),
    limit: int = Query(default=50, ge=1, le=200),
):
    return {"tokens": list_honey_tokens(status=status, limit=limit)}


@app.get("/api/tokens/stats")
def get_token_stats():
    return token_stats()
