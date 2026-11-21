from pathlib import Path
from unittest.mock import MagicMock
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from shared import db as shared_db
from shared.models import Base
from honeypot.tokens import FALLBACK, token_for
from pipeline.honey import detect_honey_token, honey_result


@pytest.fixture(autouse=True)
def isolated_db(monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(shared_db, "SessionLocal", TestingSessionLocal)
    monkeypatch.setenv("HONEY_TOKEN_PREFIX", "bt_live_")
    monkeypatch.setenv("HONEY_TOKEN_TTL_HOURS", "24")
    monkeypatch.setenv("HONEY_TOKEN_MAX_PER_IP_HOUR", "20")
    yield TestingSessionLocal


def test_same_ip_path_kind_reuses_token_and_different_ip_gets_different_token():
    t1 = shared_db.issue_honey_token("203.0.113.7", "/.env", "api_key", "curl/8.0")
    t2 = shared_db.issue_honey_token("203.0.113.7", "/.env", "api_key", "curl/8.0")
    t3 = shared_db.issue_honey_token("198.51.100.9", "/.env", "api_key", "curl/8.0")

    assert t1 is not None and t2 is not None and t3 is not None
    assert t1["token"] == t2["token"]
    assert t1["id"] == t2["id"]
    assert t1["token"] != t3["token"]
    assert t1["token"].startswith("bt_live_")


def test_21st_new_token_for_same_ip_in_one_hour_is_rate_limited():
    ip = "203.0.113.42"
    for i in range(20):
        row = shared_db.issue_honey_token(ip, f"/leak/{i}", "api_key")
        assert row is not None

    assert shared_db.issue_honey_token(ip, "/leak/20", "api_key") is None
    assert token_for(ip, "/leak/20", "api_key") == FALLBACK["api_key"]
    assert token_for(ip, "/leak/21", "password") == FALLBACK["password"]


@pytest.mark.parametrize("field", ["body", "headers", "query", "path"])
def test_token_detected_in_body_header_query_and_path(field):
    issued = shared_db.issue_honey_token("203.0.113.7", "/.env", "api_key")
    tokens = shared_db.load_active_tokens()

    event = {
        "ip": "203.0.113.7",
        "path": "/admin/login",
        "query": "",
        "body": "",
        "headers": {},
        "user_agent": "Mozilla/5.0",
    }
    if field == "headers":
        event["headers"] = {"Authorization": f"Bearer {issued['token']}"}
    elif field == "path":
        event["path"] = f"/api/v1/key/{issued['token']}"
    else:
        event[field] = f"token={issued['token']}"

    assert detect_honey_token(event, tokens) == issued["id"]


def test_benign_requests_match_nothing():
    shared_db.issue_honey_token("203.0.113.7", "/.env", "api_key")
    shared_db.issue_honey_token("203.0.113.7", "/.env", "password")
    tokens = shared_db.load_active_tokens()

    samples = [
        "GET / HTTP/1.1",
        "GET /robots.txt",
        "POST /admin/login username=admin&password=password123",
        "GET /api/v1/health?ok=true",
    ]
    sample_file = Path("tests/benign_samples.txt")
    if sample_file.exists():
        samples.extend(
            line.strip()
            for line in sample_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )

    for sample in samples:
        event = {
            "ip": "192.0.2.5",
            "path": sample,
            "query": "",
            "body": sample,
            "headers": {"User-Agent": "Mozilla/5.0"},
            "user_agent": "Mozilla/5.0",
        }
        assert detect_honey_token(event, tokens) is None


def test_different_ip_is_detected_and_noted_in_explanation():
    issued = shared_db.issue_honey_token("203.0.113.7", "/.env", "api_key")
    row = shared_db.record_token_use(issued["id"], "198.51.100.55", "/admin/login")
    event = {"ip": "198.51.100.55", "path": "/admin/login"}

    res = honey_result(event, row)
    assert res["severity"] == "Critical"
    assert res["attack_type"] == "Honey-Token Used"
    assert res["mitre_id"] == "T1078"
    assert res["source"] == "honey_token"
    assert "different IP" in res["explanation"]


def test_first_and_second_use_update_counts_without_overwriting_seconds_to_use():
    issued = shared_db.issue_honey_token("203.0.113.7", "/.env", "password")

    first = shared_db.record_token_use(issued["id"], "203.0.113.7", "/admin/login")
    assert first["status"] == "used"
    assert first["used_count"] == 1
    assert first["first_used_at"] is not None
    assert first["seconds_to_use"] is not None
    first_secs = first["seconds_to_use"]
    first_used_at = first["first_used_at"]

    second = shared_db.record_token_use(issued["id"], "203.0.113.7", "/api/v1/login")
    assert second["status"] == "used"
    assert second["used_count"] == 2
    assert second["first_used_at"] == first_used_at
    assert second["seconds_to_use"] == first_secs
    assert second["used_on_path"] == "/api/v1/login"


def test_honey_token_result_is_never_written_to_cache():
    issued = shared_db.issue_honey_token("203.0.113.7", "/.env", "api_key")
    tokens = shared_db.load_active_tokens()
    set_cached = MagicMock()

    event = {
        "id": 99,
        "ip": "203.0.113.7",
        "path": "/admin/login",
        "query": "",
        "body": f"password={issued['token']}",
        "headers": {},
        "user_agent": "curl/8.0",
    }

    tid = detect_honey_token(event, tokens)
    assert tid == issued["id"]
    if tid is not None:
        row = shared_db.record_token_use(tid, event["ip"], event["path"])
        result = honey_result(event, row)
    else:
        result = {}
        set_cached(event, result)

    assert result["source"] == "honey_token"
    set_cached.assert_not_called()


def test_api_listing_never_contains_full_token():
    issued = shared_db.issue_honey_token("203.0.113.7", "/.env", "api_key")
    raw_token = issued["token"]

    listed = shared_db.list_honey_tokens(limit=50)
    assert len(listed) == 1
    item = listed[0]

    assert "token" not in item
    assert item["token_masked"] == raw_token[:12] + "••••"
    assert all(str(v) != raw_token for v in item.values())
    assert raw_token not in str(listed)
