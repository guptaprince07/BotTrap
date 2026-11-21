import json
from datetime import datetime, timezone

from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker

from shared.config import DATABASE_URL
from shared.models import Base, Event, ClassificationCache


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
