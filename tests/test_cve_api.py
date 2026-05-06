from backend.api import cve_api


def test_get_cve():
    def fake_get(*args, **kwargs):
        class Response:
            def raise_for_status(self):
                pass

            def json(self):
                return {"vulnerabilities": [{"cve": {"id": "CVE-1234"}}]}

        return Response()

    cve_api.requests.get = fake_get

    result = cve_api.get_cve("CVE-1234")

    assert result is not None
    assert result["cve"]["id"] == "CVE-1234"


def test_get_cve_not_found():
    def fake_get(*args, **kwargs):
        class Response:
            def raise_for_status(self):
                pass

            def json(self):
                return {"vulnerabilities": []}

        return Response()

    cve_api.requests.get = fake_get

    result = cve_api.get_cve("CVE-XXXX")

    assert result is None


def test_get_all_cves():
    responses = [
        {
            "vulnerabilities": [{"cve": {"id": "CVE-1"}}],
            "totalResults": 2,
        },
        {
            "vulnerabilities": [{"cve": {"id": "CVE-2"}}],
            "totalResults": 2,
        },
    ]

    def fake_get(*args, **kwargs):
        class FakeResponse:
            def json(self):
                return responses.pop(0)

            def raise_for_status(self):
                pass

        return FakeResponse()

    cve_api.requests.get = fake_get

    result = cve_api.get_all_cves("start", "end")

    assert result == [
        {"cve": {"id": "CVE-1"}},
        {"cve": {"id": "CVE-2"}},
    ]


def test_cache():
    calls = {"count": 0}

    def fake_get_all_cves(*args, **kwargs):
        calls["count"] += 1
        return ["data"]

    cve_api.get_all_cves = fake_get_all_cves

    # reset cache
    cve_api._cache = None
    cve_api._cache_time = 0

    first = cve_api.get_cves_cached()
    second = cve_api.get_cves_cached()

    assert first == second
    assert calls["count"] == 1
