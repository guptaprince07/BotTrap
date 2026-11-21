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
from flask import jsonify, request  # or FastAPI equivalents if using FastAPI
from shared.db import list_dynamic_rules, rules_stats, set_rule_status


@app.get("/api/rules")
def api_list_rules():
    status = request.args.get("status")
    return jsonify({"rules": list_dynamic_rules(status=status)})


@app.post("/api/rules/<int:rule_id>/approve")
def api_approve_rule(rule_id: int):
    if not set_rule_status(rule_id, "active"):
        return jsonify({"error": "rule not found"}), 404
    return jsonify({"id": rule_id, "status": "active"})


@app.post("/api/rules/<int:rule_id>/reject")
def api_reject_rule(rule_id: int):
    if not set_rule_status(rule_id, "rejected"):
        return jsonify({"error": "rule not found"}), 404
    return jsonify({"id": rule_id, "status": "rejected"})


@app.post("/api/rules/<int:rule_id>/disable")
def api_disable_rule(rule_id: int):
    if not set_rule_status(rule_id, "disabled"):
        return jsonify({"error": "rule not found"}), 404
    return jsonify({"id": rule_id, "status": "disabled"})


@app.get("/api/rules/stats")
def api_rules_stats():
    return jsonify(rules_stats())
