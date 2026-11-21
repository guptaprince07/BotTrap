import json
import os
import secrets
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta

from sqlalchemy import create_engine, desc, func
from sqlalchemy.orm import sessionmaker

from shared.config import DATABASE_URL
from shared.models import Base, Event, ClassificationCache, HoneyToken, DynamicRule


# Database connection
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
    if DATABASE_URL.startswith("sqlite")
    else {}
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)


@contextmanager
def get_session():
    """Context manager for database sessions with automatic rollback and closing."""
    session = SessionLocal()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# Convert database row into dictionary
def event_to_dict(event):
    if event is None:
        return None

    data = {}

    for column in Event.__table__.columns:
        value = getattr(event, column.name)

        if isinstance(value, datetime):
            value = value.replace(
                tzinfo=timezone.utc
            ).isoformat().replace("+00:00", "Z")

        data[column.name] = value

    return data


# Create database tables
def init_db() -> None:
    Base.metadata.create_all(bind=engine)


# Insert a new event
def insert_event(event: dict) -> int:
    session = SessionLocal()

    try:
        new_event = Event(**event)
        new_event.status = "pending"

        session.add(new_event)
        session.commit()
        session.refresh(new_event)

        return new_event.id

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()


# Fetch events waiting for classification
def fetch_pending(limit: int = 10) -> list[dict]:
    session = SessionLocal()

    try:
        events = (
            session.query(Event)
            .filter(Event.status == "pending")
            .order_by(Event.created_at.asc())
            .limit(limit)
            .all()
        )

        return [event_to_dict(event) for event in events]

    finally:
        session.close()


# Update classification details
def update_classification(
    event_id: int,
    result: dict,
    status: str = "classified",
    geo: dict | None = None
) -> None:

    session = SessionLocal()

    try:
        event = session.query(Event).filter(
            Event.id == event_id
        ).first()

        if event is None:
            return

        allowed_fields = [
            "attack_type",
            "severity",
            "mitre_id",
            "mitre_name",
            "likely_tool",
            "explanation",
            "recommended_rule",
            "source"
        ]

        for field in allowed_fields:
            if field in result:
                setattr(event, field, result[field])

        event.status = status

        if geo:
            for field in ["country", "city", "lat", "lon"]:
                if field in geo:
                    setattr(event, field, geo[field])

        session.commit()

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()


# Get cached classification
def get_cached(payload_hash: str) -> dict | None:
    session = SessionLocal()

    try:
        cached = session.query(ClassificationCache).filter(
            ClassificationCache.payload_hash == payload_hash
        ).first()

        if cached is None:
            return None

        return json.loads(cached.result_json)

    finally:
        session.close()


# Save classification in cache
def set_cached(payload_hash: str, result: dict) -> None:
    session = SessionLocal()

    try:
        cached = session.query(ClassificationCache).filter(
            ClassificationCache.payload_hash == payload_hash
        ).first()

        if cached:
            cached.result_json = json.dumps(result)

        else:
            cached = ClassificationCache(
                payload_hash=payload_hash,
                result_json=json.dumps(result)
            )
            session.add(cached)

        session.commit()

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()


# Fetch events with optional filters
def query_events(
    limit=50,
    since_id=None,
    severity=None,
    attack_type=None,
    ip=None
) -> list[dict]:

    session = SessionLocal()

    try:
        query = session.query(Event)

        if since_id is not None:
            query = query.filter(Event.id > since_id)

        if severity:
            query = query.filter(Event.severity == severity)

        if attack_type:
            query = query.filter(Event.attack_type == attack_type)

        if ip:
            query = query.filter(Event.ip == ip)

        events = (
            query.order_by(desc(Event.created_at))
            .limit(limit)
            .all()
        )

        return [event_to_dict(event) for event in events]

    finally:
        session.close()


# Fetch one event by ID
def get_event(event_id: int) -> dict | None:
    session = SessionLocal()

    try:
        event = session.query(Event).filter(
            Event.id == event_id
        ).first()

        return event_to_dict(event)

    finally:
        session.close()


# ============================================================================
# Honey Token Tracking & Telemetry
# ============================================================================

def _iso_utc(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def make_token(kind: str) -> str:
    """Generate a random, >=12-char honey-token (never derived from real secrets)."""
    prefix = os.getenv("HONEY_TOKEN_PREFIX", "bt_live_")
    if kind == "api_key":
        return prefix + secrets.token_hex(6)  # e.g. bt_live_98a7f2c41b3d (20 chars)
    return secrets.token_urlsafe(9)           # 12 chars, password-like


def mask_token(token: str) -> str:
    """Return only the first 12 characters followed by masking dots."""
    return f"{token[:12]}••••"


def _token_to_dict(row: HoneyToken, *, masked: bool = True) -> dict:
    data = {
        "id": row.id,
        "created_at": _iso_utc(row.created_at),
        "kind": row.kind,
        "issued_to_ip": row.issued_to_ip,
        "issued_on_path": row.issued_on_path,
        "status": row.status,
        "used_count": row.used_count or 0,
        "first_used_at": _iso_utc(row.first_used_at),
        "last_used_at": _iso_utc(row.last_used_at),
        "used_by_ip": row.used_by_ip,
        "used_on_path": row.used_on_path,
        "seconds_to_use": row.seconds_to_use,
    }
    if masked:
        data["token_masked"] = mask_token(row.token)
    else:
        data["token"] = row.token
        data["issued_user_agent"] = row.issued_user_agent
    return data


def issue_honey_token(
    ip: str, path: str, kind: str, user_agent: str = ""
) -> dict | None:
    """
    Return an existing token for (ip, path, kind) within TTL hours, or issue a new one.
    Returns None if this IP has already generated >= MAX_PER_IP_HOUR new tokens in the last hour.
    """
    ttl_hours = int(os.getenv("HONEY_TOKEN_TTL_HOURS", "24"))
    max_per_hour = int(os.getenv("HONEY_TOKEN_MAX_PER_IP_HOUR", "20"))
    now = datetime.utcnow()

    with SessionLocal() as db:
        existing = (
            db.query(HoneyToken)
            .filter(
                HoneyToken.issued_to_ip == ip,
                HoneyToken.issued_on_path == path,
                HoneyToken.kind == kind,
                HoneyToken.created_at >= now - timedelta(hours=ttl_hours),
            )
            .order_by(HoneyToken.created_at.desc(), HoneyToken.id.desc())
            .first()
        )
        if existing:
            return _token_to_dict(existing, masked=False)

        recent_count = (
            db.query(func.count(HoneyToken.id))
            .filter(
                HoneyToken.issued_to_ip == ip,
                HoneyToken.created_at >= now - timedelta(hours=1),
            )
            .scalar()
            or 0
        )
        if recent_count >= max_per_hour:
            return None

        row = HoneyToken(
            created_at=now,
            token=make_token(kind),
            kind=kind,
            issued_to_ip=ip,
            issued_on_path=path[:512],
            issued_user_agent=(user_agent or "")[:512],
            status="issued",
            used_count=0,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return _token_to_dict(row, masked=False)


def load_active_tokens(limit: int = 5000) -> dict[str, int]:
    """Return {token_string: token_id}, newest first, for worker scanning."""
    with SessionLocal() as db:
        rows = (
            db.query(HoneyToken.token, HoneyToken.id)
            .order_by(HoneyToken.created_at.desc(), HoneyToken.id.desc())
            .limit(limit)
            .all()
        )
        return {tok: tid for tok, tid in rows}


def record_token_use(token_id: int, used_by_ip: str, used_on_path: str) -> dict:
    """
    Record a honey-token hit. First use flips status='used' and locks first_used_at & seconds_to_use.
    Subsequent uses increment used_count and update last_used_at only.
    """
    now = datetime.utcnow()
    with SessionLocal() as db:
        row = db.query(HoneyToken).filter(HoneyToken.id == token_id).first()
        if not row:
            raise ValueError(f"HoneyToken id={token_id} not found")

        seconds_since_issue = max(0, int((now - row.created_at).total_seconds()))
        row.used_count = (row.used_count or 0) + 1
        row.last_used_at = now
        row.used_by_ip = used_by_ip
        row.used_on_path = used_on_path[:512]

        if row.first_used_at is None:
            row.status = "used"
            row.first_used_at = now
            row.seconds_to_use = seconds_since_issue

        db.commit()
        db.refresh(row)
        result = _token_to_dict(row, masked=False)
        result["seconds_since_issue"] = seconds_since_issue
        return result


def list_honey_tokens(status: str | None = None, limit: int = 50) -> list[dict]:
    """Return masked token rows, newest first. Never includes the full token."""
    with SessionLocal() as db:
        query = db.query(HoneyToken)
        if status in ("issued", "used"):
            query = query.filter(HoneyToken.status == status)
        rows = (
            query.order_by(HoneyToken.created_at.desc(), HoneyToken.id.desc())
            .limit(limit)
            .all()
        )
        return [_token_to_dict(r, masked=True) for r in rows]


def token_stats() -> dict:
    """Aggregate honey-token counters for /api/tokens/stats."""
    with SessionLocal() as db:
        total_issued = db.query(func.count(HoneyToken.id)).scalar() or 0
        used_count = (
            db.query(func.count(HoneyToken.id))
            .filter(HoneyToken.status == "used")
            .scalar()
            or 0
        )
        readers = (
            db.query(func.count(func.distinct(HoneyToken.issued_to_ip))).scalar() or 0
        )
        avg_secs = (
            db.query(func.avg(HoneyToken.seconds_to_use))
            .filter(HoneyToken.seconds_to_use.isnot(None))
            .scalar()
        )
        last_used = db.query(func.max(HoneyToken.last_used_at)).scalar()

        return {
            "issued": total_issued,
            "used": used_count,
            "readers": readers,
            "avg_seconds_to_use": int(round(avg_secs)) if avg_secs is not None else 0,
            "last_used_at": _iso_utc(last_used),
        }


# ============================================================================
# Dynamic Rules Engine Storage & Telemetry
# ============================================================================

def _rule_to_dict(rule: DynamicRule) -> dict:
    return {
        "id": rule.id,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "pattern": rule.pattern,
        "target": rule.target,
        "attack_type": rule.attack_type,
        "severity": rule.severity,
        "mitre_id": rule.mitre_id,
        "mitre_name": rule.mitre_name,
        "explanation": rule.explanation,
        "recommended_rule": rule.recommended_rule,
        "status": rule.status,
        "source_event_id": rule.source_event_id,
        "hit_count": rule.hit_count or 0,
        "last_hit_at": rule.last_hit_at.isoformat() if rule.last_hit_at else None,
    }


def add_dynamic_rule(rule: dict) -> int | None:
    """Insert a rule; return its id, or None if pattern already exists."""
    with get_session() as db:
        existing = db.query(DynamicRule).filter(DynamicRule.pattern == rule["pattern"]).first()
        if existing:
            return None
        obj = DynamicRule(
            pattern=rule["pattern"],
            target=rule.get("target", "any"),
            attack_type=rule.get("attack_type"),
            severity=rule.get("severity"),
            mitre_id=rule.get("mitre_id"),
            mitre_name=rule.get("mitre_name"),
            explanation=rule.get("explanation"),
            recommended_rule=rule.get("recommended_rule"),
            status=rule.get("status", "pending_review"),
            source_event_id=rule.get("source_event_id"),
        )
        db.add(obj)
        db.commit()
        db.refresh(obj)
        return obj.id


def list_dynamic_rules(status: str | None = None) -> list[dict]:
    with get_session() as db:
        q = db.query(DynamicRule)
        if status:
            q = q.filter(DynamicRule.status == status)
        rows = q.order_by(DynamicRule.created_at.desc(), DynamicRule.id.desc()).all()
        return [_rule_to_dict(r) for r in rows]


def set_rule_status(rule_id: int, status: str) -> bool:
    if status not in {"pending_review", "active", "rejected", "disabled"}:
        return False
    with get_session() as db:
        rule = db.query(DynamicRule).filter(DynamicRule.id == rule_id).first()
        if not rule:
            return False
        rule.status = status
        db.commit()
        return True


def record_rule_hit(rule_id: int) -> None:
    with get_session() as db:
        rule = db.query(DynamicRule).filter(DynamicRule.id == rule_id).first()
        if not rule:
            return
        rule.hit_count = (rule.hit_count or 0) + 1
        rule.last_hit_at = datetime.utcnow()
        db.commit()


def rules_stats() -> dict:
    with get_session() as db:
        active_count = db.query(func.count(DynamicRule.id)).filter(DynamicRule.status == "active").scalar() or 0
        pending_count = (
            db.query(func.count(DynamicRule.id)).filter(DynamicRule.status == "pending_review").scalar() or 0
        )
        total_hits = (
            db.query(func.coalesce(func.sum(DynamicRule.hit_count), 0))
            .filter(DynamicRule.status == "active")
            .scalar()
            or 0
        )
        # Keep static count aligned with your static rule set if exposed
        if "STATIC_RULES" in globals():
            static_count = len(globals()["STATIC_RULES"])
        else:
            try:
                from pipeline.rules import COMPILED_RULES
                static_count = len(COMPILED_RULES)
            except Exception:
                static_count = 9
        return {
            "static": int(static_count),
            "active": int(active_count),
            "pending": int(pending_count),
            "total_hits": int(total_hits),
            "llm_calls_saved": int(total_hits),
        }
