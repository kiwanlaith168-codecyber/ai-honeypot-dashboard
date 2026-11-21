"""
geo.py — IP Geolocation with in-memory + SQLite caching.
Uses ip-api.com (free, no API key required).
For loopback / private IPs it returns Jordan as a demo default.
"""

import time
import logging
import requests
from config import GEO_API_URL, GEO_TIMEOUT
import database as db

logger = logging.getLogger("honeypot.geo")

# In-memory LRU-style cache (ip → {geo_dict, timestamp})
_mem_cache: dict = {}
_CACHE_TTL = 3600   # 1 hour


# Private/loopback IP ranges — return demo country (Jordan) for honeypot demos
_PRIVATE_PREFIXES = (
    "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "::1", "localhost",
)

# Demo entry for private IPs (simulates an attack from Jordan for dashboard demo)
_DEMO_GEO = {
    "status":      "success",
    "country":     "Jordan",
    "countryCode": "JO",
    "regionName":  "Amman Governorate",
    "city":        "Amman",
    "lat":         31.9539,
    "lon":         35.9106,
    "isp":         "Jordan Telecom",
    "org":         "ZAIN-JO",
    "query":       "private",
}


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def resolve_ip(ip: str) -> dict:
    """
    Return geo dict for *ip*.
    Dict keys: country, countryCode, regionName, city, lat, lon, isp, query
    """
    # Private / loopback → demo Jordan entry
    if _is_private(ip):
        logger.debug("Private IP %s → demo Jordan geo", ip)
        return dict(_DEMO_GEO, query=ip)

    # Memory cache
    cached = _mem_cache.get(ip)
    if cached and (time.time() - cached["_ts"]) < _CACHE_TTL:
        return cached

    # SQLite cache
    row = db.get_cached_geo(ip)
    if row:
        result = {
            "country":     row["country"],
            "countryCode": row["country_code"],
            "regionName":  row["region"],
            "city":        row["city"],
            "lat":         row["latitude"],
            "lon":         row["longitude"],
            "isp":         row["isp"],
            "query":       ip,
        }
        result["_ts"] = time.time()
        _mem_cache[ip] = result
        return result

    # Live lookup
    try:
        url  = GEO_API_URL.format(ip=ip)
        resp = requests.get(url, timeout=GEO_TIMEOUT)
        data = resp.json()
        if data.get("status") == "success":
            data["_ts"] = time.time()
            _mem_cache[ip] = data
            db.cache_geo(ip, data)
            logger.debug("Geo resolved  ip=%s  country=%s  city=%s",
                         ip, data.get("country"), data.get("city"))
            return data
        else:
            logger.warning("Geo failed  ip=%s  msg=%s", ip, data.get("message"))
    except Exception as exc:
        logger.warning("Geo request error  ip=%s  err=%s", ip, exc)

    # Fallback
    fallback = {
        "country": "Unknown", "countryCode": "XX",
        "regionName": "", "city": "", "lat": 0, "lon": 0,
        "isp": "", "query": ip, "_ts": time.time(),
    }
    _mem_cache[ip] = fallback
    return fallback
