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