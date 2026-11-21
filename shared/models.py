# """SQLAlchemy database models skeleton."""
from sqlalchemy import Column, Integer, String, Text, Float, DateTime
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    ip = Column(String(64), index=True)

    country = Column(String(64))
    city = Column(String(64))

    lat = Column(Float)
    lon = Column(Float)

    method = Column(String(10))
    path = Column(String(512))

    query = Column(Text)
    headers = Column(Text)
    body = Column(Text)

    user_agent = Column(String(512))

    payload_hash = Column(String(64), index=True)

    status = Column(String(16), default="pending", index=True)

    attack_type = Column(String(64))
    severity = Column(String(16))

    mitre_id = Column(String(16))
    mitre_name = Column(String(128))

    likely_tool = Column(String(64))

    explanation = Column(Text)
    recommended_rule = Column(Text)

    source = Column(String(16))


class ClassificationCache(Base):
    __tablename__ = "classification_cache"

    payload_hash = Column(String(64), primary_key=True)

    result_json = Column(Text)


from datetime import datetime
from sqlalchemy import Column, DateTime, Integer, String


class HoneyToken(Base):
    __tablename__ = "honey_tokens"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    token = Column(String(64), unique=True, index=True)
    kind = Column(String(16))  # api_key | password
    issued_to_ip = Column(String(64), index=True)
    issued_on_path = Column(String(512))  # /.env, /api/v1/config, ...
    issued_user_agent = Column(String(512))
    status = Column(String(8), default="issued", index=True)  # issued | used
    used_count = Column(Integer, default=0)
    first_used_at = Column(DateTime)
    last_used_at = Column(DateTime)
    used_by_ip = Column(String(64))
    used_on_path = Column(String(512))
    seconds_to_use = Column(Integer)  # first_used_at - created_at

import os
import secrets
from datetime import datetime, timedelta
from sqlalchemy import func
from shared.models import HoneyToken


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
