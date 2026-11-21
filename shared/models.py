# """SQLAlchemy database models skeleton."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime
from sqlalchemy.orm import declarative_base

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
    from datetime import datetime
from sqlalchemy import Column, DateTime, Integer, String, Text


class DynamicRule(Base):
    __tablename__ = "dynamic_rules"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    pattern = Column(String(200), unique=True, nullable=False)
    target = Column(String(16), default="any")  # path | query | body | user_agent | any
    attack_type = Column(String(64))
    severity = Column(String(16))
    mitre_id = Column(String(16))
    mitre_name = Column(String(128))
    explanation = Column(Text)
    recommended_rule = Column(Text)
    status = Column(String(16), default="pending_review", index=True)
    # pending_review | active | rejected | disabled
    source_event_id = Column(Integer)
    hit_count = Column(Integer, default=0)
    last_hit_at = Column(DateTime)
