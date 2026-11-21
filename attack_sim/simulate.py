import re
import time
import requests


def run_canary_scenario(target: str, attacker_ip: str = "203.0.113.7") -> None:
    target = target.rstrip("/")
    headers = {
        "X-Forwarded-For": attacker_ip,
        "User-Agent": "curl/8.5.0",
    }

    print(f"[1/3] Requesting {target}/.env as {attacker_ip} ...")
    r1 = requests.get(f"{target}/.env", headers=headers, timeout=15)
    r1.raise_for_status()

    match = re.search(r"^ADMIN_KEY=(\S+)$", r1.text, re.MULTILINE)
    if not match:
        raise RuntimeError(f"ADMIN_KEY not found in /.env response:\n{r1.text}")
    leaked_key = match.group(1)
    print(f"      Extracted ADMIN_KEY={leaked_key[:12]}••••")

    print("[2/3] Waiting 3 seconds ...")
    time.sleep(3)

    print(f"[3/3] Posting stolen key to {target}/admin/login ...")
    r2 = requests.post(
        f"{target}/admin/login",
        headers=headers,
        data={"username": "admin", "password": leaked_key},
        timeout=15,
    )
    print(f"      Response: HTTP {r2.status_code} (expected 401)")
    print("Done. Check the dashboard in ~2 seconds for the Critical alert.")
