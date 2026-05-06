import requests
import time
from datetime import datetime, timedelta

CACHE_DAYS = 30
CACHE_TTL = 3600000000000
_kev_cache = None
_kev_cache_time = 0


def get_kevs_cached() -> list[dict]:
    global _kev_cache, _kev_cache_time

    now = time.time()

    if _kev_cache is None or now - _kev_cache_time > CACHE_TTL:
        CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()

        data = response.json()
        kevs = data.get("vulnerabilities", [])

        _kev_cache = filter_recent_kevs(kevs, CACHE_DAYS)
        _kev_cache_time = now

    return _kev_cache


def filter_recent_kevs(kevs: list[dict], days: int) -> list[dict]:
    cutoff = datetime.utcnow().date() - timedelta(days=days)

    return [
        kev
        for kev in kevs
        if datetime.strptime(kev["dateAdded"], "%Y-%m-%d").date() >= cutoff
    ]
