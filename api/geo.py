"""IP geolocation lookup for HoneyLens.

Order: memory cache -> built-in table (the simulator's demo IPs, works offline)
-> ip-api.com (free, HTTP only, ~45 req/min). Private/local IPs have no location.
Failed lookups are only cached for a short time, so a blocked network or a
rate-limit hit does not leave an IP without a map pin forever.
"""

import ipaddress
import time

import requests

# Successful / definitive results: ip -> result
geo_cache = {}
# Transient failures: ip -> (result, retry_after_timestamp)
_failed = {}
RETRY_AFTER_SECONDS = 60

EMPTY = {"country": None, "city": None, "lat": None, "lon": None}

# Offline locations for the demo IPs used by attack_sim/simulate.py, so the map
# works with no internet access (college Wi-Fi, firewalls, rate limits).
KNOWN_IPS = {
    "185.220.101.4": ("Germany", "Berlin", 52.5200, 13.4050),
    "45.155.205.233": ("Russia", "Moscow", 55.7558, 37.6173),
    "103.21.244.12": ("India", "New Delhi", 28.6139, 77.2090),
    "218.92.0.107": ("China", "Nanjing", 32.0603, 118.7969),
    "104.244.42.1": ("United States", "San Francisco", 37.7749, -122.4194),
    "177.54.148.20": ("Brazil", "Sao Paulo", -23.5505, -46.6333),
    "41.203.72.18": ("Nigeria", "Lagos", 6.5244, 3.3792),
    "103.145.13.90": ("Singapore", "Singapore", 1.3521, 103.8198),
    "185.156.73.54": ("Netherlands", "Amsterdam", 52.3676, 4.9041),
    "91.132.147.168": ("France", "Paris", 48.8566, 2.3522),
    "211.234.120.55": ("South Korea", "Seoul", 37.5665, 126.9780),
    "197.232.61.12": ("Kenya", "Nairobi", -1.2921, 36.8219),
    "178.128.164.89": ("United Kingdom", "London", 51.5072, -0.1276),
    "190.14.36.91": ("Colombia", "Bogota", 4.7110, -74.0721),
    "139.59.42.110": ("India", "Mumbai", 19.0760, 72.8777),
}


def _is_private(ip: str) -> bool:
    """True for localhost, private, link-local and otherwise non-public addresses."""
    if ip == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # not a valid IP address
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def lookup_ip(ip: str) -> dict:
    """Return {"country", "city", "lat", "lon"} for an IP (None values if unknown)."""

    if ip in geo_cache:
        return geo_cache[ip]

    # Recently failed: do not hammer the service, try again after a short pause
    failed = _failed.get(ip)
    if failed and time.time() < failed[1]:
        return failed[0]

    if _is_private(ip):
        geo_cache[ip] = dict(EMPTY)
        return geo_cache[ip]

    if ip in KNOWN_IPS:
        country, city, lat, lon = KNOWN_IPS[ip]
        geo_cache[ip] = {"country": country, "city": city, "lat": lat, "lon": lon}
        return geo_cache[ip]

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
    except (requests.RequestException, ValueError):
        data = None

    if data and data.get("status") == "success":
        result = {
            "country": data.get("country"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
        }
        geo_cache[ip] = result
        return result

    # Network error, rate limit or unknown IP: remember briefly, retry later
    result = dict(EMPTY)
    _failed[ip] = (result, time.time() + RETRY_AFTER_SECONDS)
    return result