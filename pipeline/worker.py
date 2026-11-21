
"""Background pipeline worker skeleton."""
import logging
import os
import threading
import time

from ai import llm_client
from api import geo as geo_service
from pipeline.rules import classify_by_rules
from shared import db

logger = logging.getLogger("bottrap.pipeline")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

_worker_thread: threading.Thread | None = None
_stop_event = threading.Event()


def process_event(event: dict) -> None:
    """Processes a single pending event: geo -> rules -> cache -> LLM -> DB update."""
    event_id = event["id"]
    ip = event.get("ip") or ""
    payload_hash = event.get("payload_hash") or ""

    # 1. Resolve IP geolocation if latitude is missing
    geo_data = None
    if event.get("lat") is None and ip:
        try:
            geo_data = geo_service.lookup_ip(ip)
        except Exception as exc:
            logger.warning("Geo lookup failed for IP %s (event %s): %s", ip, event_id, exc)
            geo_data = None

    # 2. Try deterministic regex rules first (free & instant)
    result = classify_by_rules(event)

    # 3. Check classification cache if rules are unsure
    if result is None and payload_hash:
        cached = db.get_cached(payload_hash)
        if cached is not None:
            result = dict(cached)
            result["source"] = "cache"

    # 4. Call LLM if still unclassified, then store in cache
    if result is None:
        result = llm_client.classify_with_llm(event)
        if payload_hash and result.get("source") == "llm":
            try:
                db.set_cached(payload_hash, result)
            except Exception as exc:
                logger.warning("Failed to write cache for hash %s: %s", payload_hash, exc)

    # 5. Persist classification and geolocation to DB
    db.update_classification(event_id, result, status="classified", geo=geo_data)
    logger.info(
        "Classified event %s (%s) -> %s [%s] via %s",
        event_id,
        ip,
        result.get("attack_type"),
        result.get("severity"),
        result.get("source"),
    )


def _worker_loop(poll_interval: float = 2.0) -> None:
    """Continuously polls pending events every 2 seconds and classifies them safely."""
    logger.info("Pipeline worker started (interval=%.1fs)", poll_interval)
    while not _stop_event.is_set():
        try:
            pending_events = db.fetch_pending(limit=10)
            for event in pending_events:
                if _stop_event.is_set():
                    break
                try:
                    process_event(event)
                except Exception as exc:
                    logger.exception("Failed processing event %s: %s", event.get("id"), exc)
                    try:
                        db.update_classification(event["id"], {}, status="failed")
                    except Exception as inner_exc:
                        logger.error("Could not mark event %s as failed: %s", event.get("id"), inner_exc)
        except Exception as loop_exc:
            logger.exception("Pipeline worker loop error: %s", loop_exc)

        _stop_event.wait(poll_interval)


def start() -> None:
    """Starts the background pipeline worker thread if RUN_WORKER is enabled."""
    global _worker_thread
    run_worker = os.getenv("RUN_WORKER", "true").strip().lower()
    if run_worker not in ("1", "true", "yes"):
        logger.info("RUN_WORKER is disabled; skipping pipeline worker startup.")
        return

    if _worker_thread is not None and _worker_thread.is_alive():
        return

    _stop_event.clear()
    _worker_thread = threading.Thread(target=_worker_loop, name="bottrap-pipeline-worker", daemon=True)
    _worker_thread.start()


def stop() -> None:
    """Signals the worker thread to stop gracefully."""
    _stop_event.set()
    if _worker_thread is not None:
        _worker_thread.join(timeout=5.0)
import logging
import os
import time
from pipeline.rules import (
    classify as classify_static,
    load_active_rules,
    load_benign_samples,
    match_dynamic,
    pick_text,
    validate_suggested_regex,
)
from shared.db import add_dynamic_rule

log = logging.getLogger(__name__)

AUTO_APPROVE_RULES = os.getenv("AUTO_APPROVE_RULES", "false").strip().lower() == "true"
REFRESH_SECONDS = float(os.getenv("DYNAMIC_RULES_REFRESH_SECONDS", "10"))
BENIGN_SAMPLES = load_benign_samples()


def propose_rule(event: dict, result: dict) -> None:
    pattern = result.get("suggested_regex")
    if not pattern or result.get("source") != "llm" or result.get("attack_type") == "Other":
        return

    target = result.get("regex_target") or "any"
    ok, reason = validate_suggested_regex(pattern, pick_text(event, target), BENIGN_SAMPLES)
    if not ok:
        log.info("dynamic rule rejected (%s): %s", reason, pattern)
        return

    status = "active" if AUTO_APPROVE_RULES else "pending_review"
    rule_id = add_dynamic_rule({
        "pattern": pattern,
        "target": target,
        "status": status,
        "attack_type": result.get("attack_type"),
        "severity": result.get("severity"),
        "mitre_id": result.get("mitre_id"),
        "mitre_name": result.get("mitre_name"),
        "explanation": result.get("explanation"),
        "recommended_rule": result.get("recommended_rule"),
        "source_event_id": event.get("id"),
    })
    if rule_id is not None:
        log.info("proposed dynamic rule #%s (%s): %s", rule_id, status, pattern)


def run_worker_loop(fetch_pending, cache_lookup, llm_classify, update_classification):
    active_rules = load_active_rules()
    last_refresh = time.monotonic()

    while True:
        now = time.monotonic()
        if now - last_refresh >= REFRESH_SECONDS:
            active_rules = load_active_rules()
            last_refresh = now

        events = fetch_pending()
        for event in events:
            result = classify_static(event)
            if not result:
                result = match_dynamic(event, active_rules)
            if not result:
                result = cache_lookup(event)
            if not result:
                result = llm_classify(event)
                propose_rule(event, result)

            update_classification(event["id"], result)

        if not events:
            time.sleep(0.5)
