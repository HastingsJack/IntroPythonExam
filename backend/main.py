from fastapi import FastAPI, Query
from backend import data_processing, password_processing

app = FastAPI(title="CVE Dashboard API")


@app.get("/cves/summary")
def cves_summary(days: int = Query(7, ge=1, le=30)):
    df = data_processing.get_cve_dataframe(days)

    return {
        "metrics": {
            "total": int(data_processing.total_cves(df)),
            "critical": int(data_processing.critical_cves(df)),
            "average_cvss": float(data_processing.average_cvss(df)),
            "kev_ratio": float(data_processing.kev_ratio(df)),
        },
        "severity_counts": {
            k: int(v) for k, v in data_processing.severity_counts(df).items()
        },
        "weekday_counts": {
            day: {k: int(v) for k, v in counts.items()}
            for day, counts in data_processing.cves_by_weekday(df).items()
        },
    }


@app.get("/kevs/summary")
def kevs_summary(days: int = Query(7, ge=1, le=30)):
    df = data_processing.get_kev_dataframe(days)

    nodes = []
    edges = []
    node_ids = set()

    for _, row in df.iterrows():
        vendor = row["vendorProject"]
        product = row["product"]
        cwes = row["cwe"]
        ransomware = row["Ransomware_Known"]

        # Add CWE nodes
        for cwe in cwes:
            if cwe not in node_ids:
                nodes.append({"id": cwe, "type": "cwe"})
                node_ids.add(cwe)

        # Add Vendor node
        if vendor not in node_ids:
            nodes.append({"id": vendor, "type": "vendor"})
            node_ids.add(vendor)

        # Add edges CWE -> Vendor with product as label
        for cwe in cwes:
            edges.append(
                {
                    "source": cwe,
                    "target": vendor,
                    "product": product,
                    "ransomware": ransomware,
                }
            )

    return {
        "metrics": {
            "total": int(data_processing.total_kevs(df)),
            "top_vendor": str(data_processing.top_vendor(df)),
            "most_common_cwe": str(data_processing.most_common_cwe(df)),
            "ransomware_campaigns": int(data_processing.ransomware_campaigns(df)),
        },
        "network_graph": {"nodes": nodes, "edges": edges},
        "cwe_counts": {k: int(v) for k, v in data_processing.cwe_counts(df).items()},
    }


passwords = []


@app.get("/password/cracking")
def cracking_est(password: str = Query(...)):
    global passwords
    passwords.append(password)
    df = password_processing.password_dataframe(passwords)

    return {"data": df.to_dict(orient="records")}


@app.get("/watchlist")
def cve(cve: str):
    df = data_processing.get_watchlist_dataframe(cve)

    return df.to_dict(orient="records")
