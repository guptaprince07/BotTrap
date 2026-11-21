"""Insert fictional demo events into the BotTrap database."""

import hashlib
import json
import random
from datetime import datetime, timedelta, timezone

from shared.db import init_db, insert_event, update_classification


ATTACKS = [
    {
        "attack_type": "SQL Injection",
        "severity": "High",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "likely_tool": "sqlmap",
        "explanation": "A simulated login payload matches a SQL injection pattern.",
        "recommended_rule": "Apply SQL injection detection and blocking at the WAF.",
        "body": "DEMO: simulated SQL injection test payload",
    },
    {
        "attack_type": "XSS",
        "severity": "Medium",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "likely_tool": "browser",
        "explanation": "A simulated request contains an XSS test marker.",
        "recommended_rule": "Apply input validation and output encoding.",
        "body": "DEMO: simulated XSS test marker",
    },
    {
        "attack_type": "Brute Force",
        "severity": "Medium",
        "mitre_id": "T1110",
        "mitre_name": "Brute Force",
        "likely_tool": "unknown",
        "explanation": "Repeated simulated login attempts were detected.",
        "recommended_rule": "Rate-limit repeated login requests.",
        "body": "DEMO: repeated login attempt",
    },
    {
        "attack_type": "Path Traversal",
        "severity": "High",
        "mitre_id": "T1083",
        "mitre_name": "File and Directory Discovery",
        "likely_tool": "scanner",
        "explanation": "A simulated request resembles a path traversal probe.",
        "recommended_rule": "Block suspicious directory traversal patterns.",
        "body": "DEMO: simulated path traversal marker",
    },
    {
        "attack_type": "Vulnerability Scan",
        "severity": "Medium",
        "mitre_id": "T1595.002",
        "mitre_name": "Vulnerability Scanning",
        "likely_tool": "scanner",
        "explanation": "A simulated automated scanner request was detected.",
        "recommended_rule": "Rate-limit repeated scanning requests.",
        "body": "DEMO: simulated vulnerability scan",
    },
    {
        "attack_type": "Sensitive File Probe",
        "severity": "High",
        "mitre_id": "T1552.001",
        "mitre_name": "Credentials In Files",
        "likely_tool": "scanner",
        "explanation": "A simulated request attempted to locate a sensitive file.",
        "recommended_rule": "Deny access to sensitive configuration files.",
        "body": "DEMO: simulated sensitive file probe",
    },
]

# Reserved documentation IP addresses.
# These are fictional demo identities, not real attackers.
DEMO_IPS = [
    "192.0.2.10",
    "192.0.2.11",
    "198.51.100.10",
    "198.51.100.11",
    "203.0.113.10",
    "203.0.113.11",
    "203.0.113.12",
]

# Fictional coordinates for dashboard demonstration.
DEMO_LOCATIONS = [
    {"country": "India", "city": "Demo City 1", "lat": 28.6, "lon": 77.2},
    {"country": "USA", "city": "Demo City 2", "lat": 40.7, "lon": -74.0},
    {"country": "UK", "city": "Demo City 3", "lat": 51.5, "lon": -0.1},
    {"country": "Germany", "city": "Demo City 4", "lat": 52.5, "lon": 13.4},
    {"country": "Japan", "city": "Demo City 5", "lat": 35.7, "lon": 139.7},
]


def seed_database():
    init_db()

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    for i in range(100):
        attack = random.choice(ATTACKS)
        ip = random.choice(DEMO_IPS)
        location = random.choice(DEMO_LOCATIONS)

        method = random.choice(["GET", "POST"])
        path = random.choice([
            "/admin/login",
            "/wp-login.php",
            "/api/v1/login",
            "/.env",
            "/admin",
            "/phpmyadmin/",
        ])

        body = attack["body"]

        payload = f"{method}{path}{body}{i}"
        payload_hash = hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()

        created_at = now - timedelta(
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )

        event = {
            "created_at": created_at,
            "ip": ip,
            "method": method,
            "path": path,
            "query": "",
            "headers": json.dumps({
                "User-Agent": "BotTrap-Demo/1.0"
            }),
            "body": body,
            "user_agent": "BotTrap-Demo/1.0",
            "payload_hash": payload_hash,
        }

        event_id = insert_event(event)

        classification = {
            key: value
            for key, value in attack.items()
            if key != "body"
        }

        classification["source"] = "fallback"

        update_classification(
            event_id,
            classification,
            status="classified",
            geo=location
        )

    print("Successfully inserted 100 fictional demo events!")


if __name__ == "__main__":
    seed_database()