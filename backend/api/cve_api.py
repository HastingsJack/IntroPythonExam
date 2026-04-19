import requests
import time
from datetime import datetime, timedelta

CACHE_DAYS = 30
CACHE_TTL = 3600000000000
_cache = None
_cache_time = 0


def get_all_cves(pub_start: str, pub_end: str) -> list:
    all_cves = []
    start_index = 0
    page_size = 2000
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    HEADERS = {
        "User-Agent": "my-cve-dashboard-project-EK",
        "Accept": "application/json",
    }

    while True:
        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "startIndex": start_index,
            "resultsPerPage": page_size,
        }
        response = requests.get(BASE_URL, headers=HEADERS, params=params)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break
        all_cves.extend(vulnerabilities)
        start_index += page_size
        if start_index >= data.get("totalResults", 0):
            break
    return all_cves


def get_cves_cached() -> list:
    """Fetch CVEs with caching to avoid repeated API calls."""
    global _cache, _cache_time
    now = time.time()
    if _cache is None or now - _cache_time > CACHE_TTL:
        pub_start = (datetime.utcnow() - timedelta(days=CACHE_DAYS)).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"
        pub_end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        _cache = get_all_cves(pub_start, pub_end)
        _cache_time = now
    return _cache


def get_cve(cve: str):
    BASE_URL = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    HEADERS = {
        "User-Agent": "my-cve-dashboard-project-EK",
        "Accept": "application/json",
    }
    response = requests.get(BASE_URL, headers=HEADERS)
    response.raise_for_status()
    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        return None

    return vulnerabilities[0]
