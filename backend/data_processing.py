import pandas as pd
from datetime import datetime, timedelta
from backend.api.cve_api import get_cves_cached, get_cve
from backend.api.kev_api import get_kevs_cached
import json


def get_cve_dataframe(days: int) -> pd.DataFrame:
    cves = get_cves_cached()
    kevs = get_kevs_cached()
    kev_ids = {v["cveID"] for v in kevs}

    today = datetime.utcnow().date()
    cutoff = today - timedelta(days=days - 1)

    data = []
    #print(json.dumps(kevs, indent=2))
    for cve in cves:
        metrics = cve["cve"].get("metrics", {})
        cvss_list = metrics.get("cvssMetricV31", [])
        if not cvss_list:
            continue
        published = cve["cve"].get("published")
        dt = datetime.fromisoformat(published.replace("Z", "")).date()
        if dt < cutoff:
            continue
        cve_id = cve["cve"]["id"]

        data.append(
            {
                "id": cve_id,
                "severity": cvss_list[0]["cvssData"]["baseSeverity"],
                "score": cvss_list[0]["cvssData"]["baseScore"],
                "is_kev": cve_id in kev_ids,
                "published_date": dt,
            }
        )

    return pd.DataFrame(data)


def total_cves(df: pd.DataFrame) -> int:
    return len(df)


def kev_ratio(df: pd.DataFrame) -> float:
    if df.empty:
        return 0.0
    return df["is_kev"].sum() / len(df)


def critical_cves(df: pd.DataFrame) -> int:
    return df["severity"].value_counts().get("CRITICAL", 0)


def average_cvss(df: pd.DataFrame) -> float:
    if df.empty:
        return 0
    return df["score"].mean()


def severity_counts(df: pd.DataFrame) -> dict:
    return df["severity"].value_counts().to_dict()


def cves_by_weekday(df: pd.DataFrame) -> dict:
    grouped = (
        df.groupby(["published_date", "severity"])
        .size()
        .unstack(fill_value=0)
        .sort_index()
    )
    return {
        date.strftime("%a %m-%d"): row.to_dict() for date, row in grouped.iterrows()
    }


def get_kev_dataframe(days: int) -> pd.DataFrame:
    kevs = get_kevs_cached()

    data = []

    today = datetime.utcnow().date()
    cutoff = today - timedelta(days=days - 1)

    for kev in kevs:
        published = kev["dateAdded"]
        dt = datetime.strptime(published, "%Y-%m-%d").date()
        if dt < cutoff:
            continue
        kev_cve_id = kev["cveID"]
        data.append(
            {
                "id": kev_cve_id,
                "dateAdded": dt,
                "product": kev["product"],
                "vendorProject": kev["vendorProject"],
                "Ransomware_Known": kev["knownRansomwareCampaignUse"],
                "cwe": kev["cwes"],
            }
        )

    return pd.DataFrame(data)


def total_kevs(df: pd.DataFrame) -> int:
    return len(df)


def top_vendor(df: pd.DataFrame) -> str:
    if df.empty:
        return "-"
    return df["vendorProject"].value_counts().idxmax()


def most_common_cwe(df: pd.DataFrame) -> str:
    if df.empty or "cwe" not in df.columns:
        return "-"
    kev_cwe_flat = df.explode("cwe")
    cwe_count = kev_cwe_flat["cwe"].value_counts()
    if cwe_count.empty:
        return "-"
    return cwe_count.idxmax()


def cwe_counts(df: pd.DataFrame) -> dict:
    if df.empty or "cwe" not in df.columns:
        return {}

    kev_cwe_flat = df.explode("cwe")

    return kev_cwe_flat["cwe"].value_counts().sort_values(ascending=True).to_dict()


def ransomware_campaigns(df: pd.DataFrame) -> int:
    if df.empty:
        return 0
    return (df["Ransomware_Known"] == "Known").sum()


def get_watchlist_dataframe(cve: str) -> pd.DataFrame:
    cve = get_cve(cve)

    cve_data = cve["cve"]
    print(json.dumps(cve_data, indent=2))
    cwes = []
    for w in cve_data.get("weaknesses", []):
        for d in w.get("description", []):
            if d:
                cwes.append(d.get("value", "N/A"))

    data = [
        {
            "id": cve_data["id"],
            "severity": cve_data["metrics"]["cvssMetricV40"][0]["cvssData"][
                "baseSeverity"
            ],
            "score": cve_data["metrics"]["cvssMetricV40"][0]["cvssData"]["baseScore"],
            "cwes": cwes,
        }
    ]

    return pd.DataFrame(data)
