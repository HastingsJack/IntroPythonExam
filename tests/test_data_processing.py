import pandas as pd
from backend import data_processing as dp


fake_cves = [
    {
        "cve": {
            "id": "CVE-1",
            "published": "2099-01-10T00:00:00Z",
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseSeverity": "HIGH", "baseScore": 7.5}}
                ]
            },
        }
    }
]


fake_kevs = [
    {
        "dateAdded": "2099-01-10",
        "cveID": "CVE-1",
        "product": "ProductA",
        "vendorProject": "VendorA",
        "knownRansomwareCampaignUse": "Known",
        "cwes": ["CWE-79"],
    }
]


fake_watchlist_response = {
    "cve": {
        "id": "CVE-123",
        "metrics": {
            "cvssMetricV40": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.5}}]
        },
        "weaknesses": [{"description": [{"value": "CWE-79"}]}],
    }
}


def fake_get_cves_cached():
    return fake_cves


def fake_get_kevs_cached():
    return fake_kevs


def fake_get_cve(_):
    return fake_watchlist_response


def fake_get_cve_none(_):
    return None


def test_get_cve_dataframe(monkeypatch):
    monkeypatch.setattr(dp, "get_cves_cached", fake_get_cves_cached)
    monkeypatch.setattr(dp, "get_kevs_cached", fake_get_kevs_cached)

    df = dp.get_cve_dataframe(30)

    assert isinstance(df, pd.DataFrame)
    assert not df.empty
    assert "id" in df.columns
    assert "severity" in df.columns
    assert "score" in df.columns
    assert "is_kev" in df.columns


def test_get_kev_dataframe(monkeypatch):
    monkeypatch.setattr(dp, "get_kevs_cached", fake_get_kevs_cached)

    df = dp.get_kev_dataframe(30)

    assert isinstance(df, pd.DataFrame)
    assert not df.empty
    assert df.iloc[0]["id"] == "CVE-1"


def test_get_watchlist_dataframe(monkeypatch):
    monkeypatch.setattr(dp, "get_cve", fake_get_cve)

    df = dp.get_watchlist_dataframe("CVE-123")

    assert isinstance(df, pd.DataFrame)
    assert not df.empty
    assert df.iloc[0]["id"] == "CVE-123"
    assert df.iloc[0]["severity"] == "HIGH"


def test_get_watchlist_dataframe_empty(monkeypatch):
    monkeypatch.setattr(dp, "get_cve", fake_get_cve_none)

    df = dp.get_watchlist_dataframe("CVE-NOT-FOUND")

    assert df.empty


def test_total_cves():
    df = pd.DataFrame([{}, {}, {}])
    assert dp.total_cves(df) == 3


def test_kev_ratio():
    df = pd.DataFrame({"is_kev": [True, False, True]})
    assert dp.kev_ratio(df) == 2 / 3


def test_average_cvss():
    df = pd.DataFrame({"score": [5, 10]})
    assert dp.average_cvss(df) == 7.5


def test_severity_counts():
    df = pd.DataFrame({"severity": ["HIGH", "LOW", "HIGH"]})
    result = dp.severity_counts(df)

    assert result["HIGH"] == 2
    assert result["LOW"] == 1


def test_top_vendor():
    df = pd.DataFrame({"vendorProject": ["A", "A", "B"]})
    assert dp.top_vendor(df) == "A"


def test_most_common_cwe():
    df = pd.DataFrame({"cwe": [["CWE-1"], ["CWE-1"], ["CWE-2"]]})
    assert dp.most_common_cwe(df) == "CWE-1"


def test_ransomware_campaigns():
    df = pd.DataFrame({"Ransomware_Known": ["Known", "Unknown", "Known"]})
    assert dp.ransomware_campaigns(df) == 2
