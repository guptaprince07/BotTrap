"""Regex rules classification engine skeleton."""
import json
import re
import time
from collections import defaultdict, deque
from pathlib import Path

# Load MITRE technique mappings from shared/mitre.json
MITRE_PATH = Path(__file__).resolve().parent.parent / "shared" / "mitre.json"
try:
    with open(MITRE_PATH, "r", encoding="utf-8") as f:
        MITRE_MAP = json.load(f)
except FileNotFoundError:
    MITRE_MAP = {}

# In-memory sliding window tracker for brute-force detection: ip -> deque of timestamps
_LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)
BRUTE_FORCE_WINDOW_SEC = 60.0
BRUTE_FORCE_THRESHOLD = 5

LOGIN_PATHS = {
    "/admin",
    "/admin/login",
    "/administrator",
    "/wp-login.php",
    "/wp-admin",
    "/login",
    "/phpmyadmin/",
    "/api/v1/login",
}

# Deterministic rules ordered from highest severity (Critical) to lowest (Low)
COMPILED_RULES = [
    {
        "attack_type": "Command Injection",
        "severity": "Critical",
        "mitre_id": "T1059",
        "likely_tool": "curl/bash",
        "explanation": "OS shell metacharacters or command execution primitives detected in request.",
        "recommended_rule": r'if ($args ~* "(;|\||`|\$\()") { return 403; }',
        "patterns": [
            re.compile(r";\s*(cat|ls|wget|curl|id|whoami|uname|nc|bash|sh)\b", re.IGNORECASE),
            re.compile(r"\|\s*\w+", re.IGNORECASE),
            re.compile(r"\$\(", re.IGNORECASE),
            re.compile(r"`[^`]+`", re.IGNORECASE),
        ],
        "target": "payload",
    },
    {
        "attack_type": "Web Shell Upload",
        "severity": "Critical",
        "mitre_id": "T1505.003",
        "likely_tool": "weevely/curl",
        "explanation": "Attempt to upload or drop an executable server-side script file.",
        "recommended_rule": r'location ~* \.(php|jsp|asp|aspx)$ { client_max_body_size 1k; deny all; }',
        "patterns": [
            re.compile(r"filename\s*=\s*[\"']?[^\"';\r\n]+\.(php\d?|jsp|jspx|asp|aspx|phtml)", re.IGNORECASE),
            re.compile(r"Content-Disposition:\s*form-data.*\.(php|jsp|asp)", re.IGNORECASE),
            re.compile(r"<\?php\s+(eval|system|exec|passthru|shell_exec)\s*\(", re.IGNORECASE),
        ],
        "target": "full",
    },
    {
        "attack_type": "SQL Injection",
        "severity": "High",
        "mitre_id": "T1190",
        "likely_tool": "sqlmap",
        "explanation": "SQL syntax manipulation detected attempting to bypass authentication or extract database records.",
        "recommended_rule": r'if ($request_body ~* "(\x27|%27)\s*(or|and)\s+\d+=\d+|union\s+select") { return 403; }',
        "patterns": [
            re.compile(r"('|%27)\s*(or|and)\s+\d+=\d+", re.IGNORECASE),
            re.compile(r"union\s+(all\s+)?select", re.IGNORECASE),
            re.compile(r"sleep\(\d+\)", re.IGNORECASE),
            re.compile(r"benchmark\(\d+,", re.IGNORECASE),
            re.compile(r"--\s*$", re.IGNORECASE),
            re.compile(r"information_schema", re.IGNORECASE),
        ],
        "target": "payload",
    },
    {
        "attack_type": "Path Traversal",
        "severity": "High",
        "mitre_id": "T1083",
        "likely_tool": "dotdotpwn/curl",
        "explanation": "Directory traversal sequences detected attempting to read restricted filesystem files.",
        "recommended_rule": r'if ($request_uri ~* "(\.\./|%2e%2e|/etc/passwd|boot\.ini)") { return 403; }',
        "patterns": [
            re.compile(r"\.\./", re.IGNORECASE),
            re.compile(r"%2e%2e", re.IGNORECASE),
            re.compile(r"/etc/passwd", re.IGNORECASE),
            re.compile(r"boot\.ini", re.IGNORECASE),
            re.compile(r"win\.ini", re.IGNORECASE),
        ],
        "target": "payload",
    },
    {
        "attack_type": "Sensitive File Probe",
        "severity": "High",
        "mitre_id": "T1552.001",
        "likely_tool": "ffuf/gobuster",
        "explanation": "Direct request targeting exposed configuration, environment, or backup files.",
        "recommended_rule": r'location ~* /(\.env|\.git|config\.php|backup\.sql) { deny all; return 404; }',
        "patterns": [
            re.compile(r"^/(\.env|\.git/config|config\.php|backup\.sql|wp-config\.php\.bak)$", re.IGNORECASE),
        ],
        "target": "path",
    },
    {
        "attack_type": "XSS",
        "severity": "Medium",
        "mitre_id": "T1190",
        "likely_tool": "xsstrike/browser",
        "explanation": "Cross-site scripting payload attempting to inject executable JavaScript into responses.",
        "recommended_rule": r'if ($args ~* "(<script|onerror\s*=|javascript:|<svg[^>]*onload)") { return 403; }',
        "patterns": [
            re.compile(r"<script", re.IGNORECASE),
            re.compile(r"onerror\s*=", re.IGNORECASE),
            re.compile(r"javascript:", re.IGNORECASE),
            re.compile(r"<svg[^>]*onload", re.IGNORECASE),
        ],
        "target": "payload",
    },
    {
        "attack_type": "Vulnerability Scan",
        "severity": "Medium",
        "mitre_id": "T1595.002",
        "likely_tool": "scanner",
        "explanation": "Automated security scanner signature identified in the HTTP User-Agent header.",
        "recommended_rule": r'if ($http_user_agent ~* "(nikto|nmap|masscan|zgrab|nuclei|dirbuster)") { return 403; }',
        "patterns": [
            re.compile(r"(nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wpscan)", re.IGNORECASE),
        ],
        "target": "user_agent",
    },
]


def _extract_scanner_tool(user_agent: str) -> str:
    """Extracts the matched vulnerability scanner name from User-Agent."""
    for tool in ("nikto", "nmap", "masscan", "zgrab", "nuclei", "dirbuster", "gobuster", "wpscan"):
        if tool in user_agent.lower():
            return tool
    return "scanner"


def _is_brute_force(ip: str, method: str, path: str) -> bool:
    """Tracks POST requests to login paths per IP within a 60-second sliding window."""
    if not ip or method != "POST":
        return False
    normalized_path = path.rstrip("/") or "/"
    if normalized_path not in LOGIN_PATHS and path not in LOGIN_PATHS:
        return False

    now = time.time()
    timestamps = _LOGIN_ATTEMPTS[ip]
    timestamps.append(now)

    while timestamps and (now - timestamps[0]) > BRUTE_FORCE_WINDOW_SEC:
        timestamps.popleft()

    return len(timestamps) >= BRUTE_FORCE_THRESHOLD


def classify_by_rules(event: dict) -> dict | None:
    """
    Classifies a captured HTTP event using deterministic regex rules.
    Returns a classification dict matching Section 5.3, or None if unsure.
    """
    method = (event.get("method") or "GET").upper()
    path = event.get("path") or ""
    query = event.get("query") or ""
    body = event.get("body") or ""
    headers = event.get("headers") or ""
    user_agent = event.get("user_agent") or ""
    ip = event.get("ip") or ""

    payload_surface = f"{path} {query} {body}"
    full_surface = f"{payload_surface} {headers}"

    # 1. Check ordered regex rules (Critical -> High -> Medium)
    for rule in COMPILED_RULES:
        target = rule["target"]
        if target == "path":
            text_to_check = path
        elif target == "user_agent":
            text_to_check = user_agent
        elif target == "full":
            text_to_check = full_surface
        else:
            text_to_check = payload_surface

        for pattern in rule["patterns"]:
            if pattern.search(text_to_check):
                mitre_id = rule["mitre_id"]
                likely_tool = (
                    _extract_scanner_tool(user_agent)
                    if rule["attack_type"] == "Vulnerability Scan"
                    else rule["likely_tool"]
                )
                return {
                    "attack_type": rule["attack_type"],
                    "severity": rule["severity"],
                    "mitre_id": mitre_id,
                    "mitre_name": MITRE_MAP.get(mitre_id, "Exploit Public-Facing Application"),
                    "likely_tool": likely_tool,
                    "explanation": rule["explanation"],
                    "recommended_rule": rule["recommended_rule"],
                    "source": "rule",
                }

    # 2. Check high-frequency POST requests to login paths (Medium)
    if _is_brute_force(ip, method, path):
        mitre_id = "T1110"
        return {
            "attack_type": "Brute Force",
            "severity": "Medium",
            "mitre_id": mitre_id,
            "mitre_name": MITRE_MAP.get(mitre_id, "Brute Force"),
            "likely_tool": "hydra/script",
            "explanation": "Multiple rapid POST authentication attempts detected from the same source IP.",
            "recommended_rule": "limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;",
            "source": "rule",
        }

    # 3. Check plain GET reconnaissance on login endpoints with no payload (Low)
    normalized_path = path.rstrip("/") or "/"
    if method == "GET" and (normalized_path in LOGIN_PATHS or path in LOGIN_PATHS) and not query and not body:
        mitre_id = "T1595"
        return {
            "attack_type": "Recon",
            "severity": "Low",
            "mitre_id": mitre_id,
            "mitre_name": MITRE_MAP.get(mitre_id, "Active Scanning"),
            "likely_tool": "browser/crawler",
            "explanation": "Unauthenticated GET request probing an administrative login endpoint.",
            "recommended_rule": "allow 10.0.0.0/8; deny all; # Restrict admin portal to internal VPN",
            "source": "rule",
        }

    # Unsure -> delegate to cache / LLM in worker.py
    return None
from pathlib import Path
import regex

MAX_LEN = 200
NESTED_QUANT = regex.compile(r"\((?:[^()]*[+*][^()]*)\)[+*{]")

BENIGN_SAMPLES_PATH = Path(__file__).resolve().parent.parent / "tests" / "benign_samples.txt"


def load_benign_samples(path: Path = BENIGN_SAMPLES_PATH) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def pick_text(event: dict, target: str) -> str:
    if target == "path":
        return event.get("path") or ""
    if target == "query":
        return event.get("query") or ""
    if target == "body":
        return event.get("body") or ""
    if target == "user_agent":
        return event.get("user_agent") or ""
    return (
        f'{event.get("method", "")} '
        f'{event.get("path", "")}?{event.get("query", "")} '
        f'{event.get("body", "")} '
        f'{event.get("user_agent", "")}'
    )


def validate_suggested_regex(pattern, haystack, benign_samples):
    """Return (ok, reason). haystack = the text of the attack that produced the regex."""
    if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_LEN:
        return False, "empty or too long"
    if NESTED_QUANT.search(pattern):
        return False, "nested quantifier (ReDoS risk)"
    try:
        rx = regex.compile(pattern, regex.IGNORECASE)
    except regex.error:
        return False, "does not compile"
    try:
        if rx.search("", timeout=0.05):
            return False, "matches empty string"
        if not rx.search(haystack or "", timeout=0.05):
            return False, "does not match the attack it came from"
        for b in benign_samples:
            if rx.search(b, timeout=0.05):
                return False, "matches benign traffic"
        rx.search("a" * 5000, timeout=0.05)
    except TimeoutError:
        return False, "too slow"
    return True, "ok"
from shared.db import list_dynamic_rules, record_rule_hit


def load_active_rules() -> list[dict]:
    """Load active rules with precompiled case-insensitive regexes."""
    compiled_rules = []
    for r in list_dynamic_rules(status="active"):
        try:
            r["rx"] = regex.compile(r["pattern"], regex.IGNORECASE)
            compiled_rules.append(r)
        except regex.error:
            continue
    return compiled_rules


def match_dynamic(event, active_rules):
    """active_rules: list of dicts with a compiled regex in r["rx"], reloaded every
    DYNAMIC_RULES_REFRESH_SECONDS so an approved rule works without a restart."""
    for r in active_rules:
        try:
            if r["rx"].search(pick_text(event, r["target"]), timeout=0.05):
                record_rule_hit(r["id"])
                return {
                    "attack_type": r["attack_type"],
                    "severity": r["severity"],
                    "mitre_id": r["mitre_id"],
                    "mitre_name": r["mitre_name"],
                    "likely_tool": "unknown",
                    "explanation": r["explanation"],
                    "recommended_rule": r["recommended_rule"],
                    "source": "dynamic",
                }
        except TimeoutError:
            continue
    return None
