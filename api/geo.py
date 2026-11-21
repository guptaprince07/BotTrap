"""IP geolocation lookup for HoneyLens."""

import requests

# Store previously fetched IP locations
geo_cache = {}


def lookup_ip(ip: str) -> dict:
    """Return country, city, latitude and longitude for an IP."""

    # Return cached result if already checked
    if ip in geo_cache:
        return geo_cache[ip]

    # Default result for private or invalid IPs
    empty_result = {
        "country": None,
        "city": None,
        "lat": None,
        "lon": None
    }

    # Handle private/local IP addresses
    if (
        ip == "localhost"
        or ip.startswith("127.")
        or ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.")
    ):
        geo_cache[ip] = empty_result
        return empty_result

    try:
        url = f"http://ip-api.com/json/{ip}"

        response = requests.get(url, timeout=5)
        data = response.json()

        if data.get("status") == "success":
            result = {
                "country": data.get("country"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon")
            }
        else:
            result = empty_result

    except requests.RequestException:
        result = empty_result

    except ValueError:
        result = empty_result

    geo_cache[ip] = result

    return result
