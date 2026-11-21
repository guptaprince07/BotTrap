"""Rules engine unit tests skeleton."""
from pipeline import rules


def _make_event(**overrides) -> dict:
    base = {
        "ip": "203.0.113.50",
        "method": "GET",
        "path": "/",
        "query": "",
        "headers": "{}",
        "body": "",
        "user_agent": "Mozilla/5.0",
    }
    base.update(overrides)
    return base


def test_sqli_tautology_in_body():
    event = _make_event(
        method="POST",
        path="/admin/login",
        body="username=admin&password=' OR 1=1 --",
        user_agent="sqlmap/1.7",
    )
    res = rules.classify_by_rules(event)
    assert res is not None
    assert res["attack_type"] == "SQL Injection"
    assert res["severity"] == "High"
    assert res["mitre_id"] == "T1190"
    assert res["source"] == "rule"
    assert res["recommended_rule"]


def test_sqli_union_select_in_query():
    event = _make_event(
        method="GET",
        path="/api/v1/users",
        query="id=1 UNION SELECT username, password FROM users",
    )
    res = rules.classify_by_rules(event)
    assert res is not None
    assert res["attack_type"] == "SQL Injection"
    assert res["severity"] == "High"


def test_xss_script_tag():
    event = _make_event(
        method="GET",
        path="/login",
        query="error=<script>alert(1)</script>",
    )
    res = rules.classify_by_rules(event)
    assert res is not None
    assert res["attack_type"] == "XSS"
    assert res["severity"] == "Medium"
    assert res["mitre_id"] == "T1190"


def test_xss_svg_onload():
    event = _make_event(
        method="POST",
        path="/api/v1/users",
        body='{"name": "<svg/onload=alert(1)>"}',
    )
    res = rules.classify_by_rules(event)
    assert res is not None
    assert res["attack_type"] == "XSS"


def test_path_traversal_etc_passwd():
    event = _make_event(
        method="GET",
        path="/api/v1/config",
        query="file=../../../../etc/passwd",
    )
    res = rules.classify_by_rules(event)
    assert res is not None
    assert res["attack_type"] == "Path Traversal"
    assert res["severity"] == "High"
    assert res["mitre_id"] == "T1083"


def test_path_traversal_encoded():
    event = _make_event(
        method="GET",
        path="/admin",
        query="view=%2e%2e/%2e%2e/boot.ini",
    )
    res = rules.classify_by_rules(event)
    assert res is not None
    assert res["attack_type"] == "Path Traversal"


def test_command_injection_semicolon_cat():
    event = _make_event(
        method="POST",
        path="/api/v1/config",
        body="host=127.0.0.1; cat /etc/passwd",
    )
    res = rules.classify_by_rules(event)
    assert res is not None
    assert res["attack_type"] == "Command Injection"
    assert res["severity"] == "Critical"
    assert res["mitre_id"] == "T1059"


def test_command_injection_subshell():
    event = _make_event(
        method="GET",
        path="/admin/login",
        query="debug=$(whoami)",
    )
    res = rules.classify_by_rules(event)
    assert res is not None
    assert res["attack_type"] == "Command Injection"
    assert res["severity"] == "Critical"


def test_sensitive_file_probe_env():
    event = _make_event(method="GET", path="/.env")
    res = rules.classify_by_rules(event)
    assert res is not None
    assert res["attack_type"] == "Sensitive File Probe"
    assert res["severity"] == "High"
    assert res["mitre_id"] == "T1552.001"


def test_vulnerability_scan_nikto():
    event = _make_event(
        method="GET",
        path="/phpmyadmin/",
        user_agent="Mozilla/5.00 (Nikto/2.1.6)",
    )
    res = rules.classify_by_rules(event)
    assert res is not None
    assert res["attack_type"] == "Vulnerability Scan"
    assert res["severity"] == "Medium"
    assert res["mitre_id"] == "T1595.002"
    assert res["likely_tool"] == "nikto"


def test_webshell_upload_php():
    event = _make_event(
        method="POST",
        path="/wp-admin",
        body='Content-Disposition: form-data; name="file"; filename="backdoor.php"\r\n<?php system($_GET["x"]); ?>',
    )
    res = rules.classify_by_rules(event)
    assert res is not None
    assert res["attack_type"] == "Web Shell Upload"
    assert res["severity"] == "Critical"
    assert res["mitre_id"] == "T1505.003"


def test_brute_force_multiple_logins():
    rules._LOGIN_ATTEMPTS.clear()
    attacker_ip = "198.51.100.99"
    res = None
    for idx in range(rules.BRUTE_FORCE_THRESHOLD):
        event = _make_event(
            ip=attacker_ip,
            method="POST",
            path="/admin/login",
            body=f"username=admin&password=guess{idx}",
        )
        res = rules.classify_by_rules(event)

    assert res is not None
    assert res["attack_type"] == "Brute Force"
    assert res["severity"] == "Medium"
    assert res["mitre_id"] == "T1110"


def test_recon_plain_get_login():
    event = _make_event(method="GET", path="/wp-login.php")
    res = rules.classify_by_rules(event)
    assert res is not None
    assert res["attack_type"] == "Recon"
    assert res["severity"] == "Low"
    assert res["mitre_id"] == "T1595"


def test_unknown_payload_returns_none_for_llm():
    event = _make_event(
        method="POST",
        path="/api/v1/users",
        body='{"__proto__": {"isAdmin": true}}',
    )
    assert rules.classify_by_rules(event) is None
