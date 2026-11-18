"""HTTP layer of the web backend: limits, key refusal, security headers. No key, no network."""

import json

import pytest
from fastapi.testclient import TestClient

from backend.app import CSP, RateLimiter, create_app
from fakes import EXTRACTION, GOOD_DRAFT


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(rate_per_minute=1000, web_dir=tmp_path))


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["attack_version"] == "20.1"
    assert r.headers["content-security-policy"] == CSP
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "access-control-allow-origin" not in r.headers


def test_prompt_and_check_round_trip(client):
    r = client.post("/api/prompt", json={"stage": "extract", "input": "detect encoded powershell"})
    assert r.status_code == 200 and "<untrusted_input" in r.json()["user"]

    r = client.post("/api/prompt", json={"stage": "draft", "extraction": EXTRACTION, "attempt": 1})
    assert r.status_code == 200 and r.json()["purpose"] == "draft attempt 1"

    r = client.post("/api/check", json={"draft": GOOD_DRAFT})
    assert r.status_code == 200
    body = r.json()
    assert body["passed"] and body["result"]["slug"] == "win_proc_certutil_download"


def test_service_errors_are_400_with_a_message(client):
    r = client.post("/api/prompt", json={"stage": "nope"})
    assert r.status_code == 400 and "'stage'" in r.json()["error"]


def test_invalid_json_is_400(client):
    r = client.post("/api/check", content=b"{not json", headers={"content-type": "application/json"})
    assert r.status_code == 400 and "valid JSON" in r.json()["error"]


@pytest.mark.parametrize("header", ["Authorization", "x-api-key", "anthropic-api-key"])
def test_requests_carrying_a_key_are_refused(client, header):
    r = client.post("/api/check", json={"draft": GOOD_DRAFT}, headers={header: "sk-ant-api03-FAKEFAKEFAKE"})
    assert r.status_code == 400
    assert "never accepts API keys" in r.json()["error"]
    assert "FAKE" not in r.text


def test_oversized_body_is_413(tmp_path):
    c = TestClient(create_app(rate_per_minute=1000, max_body=1000, web_dir=tmp_path))
    r = c.post("/api/prompt", json={"stage": "extract", "input": "x" * 2000})
    assert r.status_code == 413


def test_rate_limit_is_429_with_retry_after(tmp_path):
    c = TestClient(create_app(rate_per_minute=2, web_dir=tmp_path))
    req = {"stage": "extract", "input": "detect encoded powershell"}
    assert c.post("/api/prompt", json=req).status_code == 200
    assert c.post("/api/prompt", json=req).status_code == 200
    r = c.post("/api/prompt", json=req)
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert c.get("/api/health").status_code == 200  # GETs aren't limited


def test_rate_limiter_window_slides():
    rl = RateLimiter(2)
    assert rl.allow("a", now=0)[0] and rl.allow("a", now=1)[0]
    assert rl.allow("a", now=2) == (False, 59)
    assert rl.allow("b", now=2)[0]  # per client
    assert rl.allow("a", now=60.5)[0]  # first hit aged out


def test_serves_the_static_page_with_headers(tmp_path):
    (tmp_path / "index.html").write_text("<!doctype html><title>t</title>", encoding="utf-8")
    c = TestClient(create_app(web_dir=tmp_path))
    r = c.get("/")
    assert r.status_code == 200 and "<title>t</title>" in r.text
    assert r.headers["content-security-policy"] == CSP
    assert r.headers["x-frame-options"] == "DENY"


def test_no_interactive_docs(client):
    assert client.get("/docs").status_code == 404


def test_unexpected_errors_do_not_leak(tmp_path, monkeypatch):
    from ringtail import service

    def boom(*_a, **_k):
        raise RuntimeError("secret internals sk-ant-api03-FAKEFAKEFAKE")

    monkeypatch.setattr(service, "check", boom)
    c = TestClient(create_app(web_dir=tmp_path), raise_server_exceptions=False)
    r = c.post("/api/check", content=json.dumps({"draft": {}}), headers={"content-type": "application/json"})
    assert r.status_code == 500
    assert "internals" not in r.text and "FAKE" not in r.text


REQ = {"stage": "extract", "input": "detect encoded powershell"}


def test_rate_limit_keys_on_the_configured_proxy_header(tmp_path):
    c = TestClient(create_app(rate_per_minute=1, ip_header="x-real-ip", web_dir=tmp_path))
    # Forged X-Forwarded-For values change every time; the proxy-set X-Real-IP doesn't.
    h1 = {"x-real-ip": "203.0.113.7", "x-forwarded-for": "1.1.1.1"}
    h2 = {"x-real-ip": "203.0.113.7", "x-forwarded-for": "2.2.2.2, 203.0.113.9"}
    assert c.post("/api/prompt", json=REQ, headers=h1).status_code == 200
    assert c.post("/api/prompt", json=REQ, headers=h2).status_code == 429
    # A different real client still gets through.
    assert c.post("/api/prompt", json=REQ, headers={"x-real-ip": "203.0.113.8"}).status_code == 200


def test_proxy_headers_ignored_unless_configured(tmp_path):
    c = TestClient(create_app(rate_per_minute=1, ip_header=None, web_dir=tmp_path))
    assert c.post("/api/prompt", json=REQ, headers={"x-real-ip": "198.51.100.1"}).status_code == 200
    assert c.post("/api/prompt", json=REQ, headers={"x-real-ip": "198.51.100.2",
                                                     "x-forwarded-for": "198.51.100.3"}).status_code == 429


def test_open_by_default(client):
    assert client.get("/api/health").json()["access_code_required"] is False
    assert client.post("/api/prompt", json=REQ).status_code == 200


def test_access_code_locks_the_api_but_not_health_or_page(tmp_path):
    (tmp_path / "index.html").write_text("<!doctype html><title>t</title>", encoding="utf-8")
    c = TestClient(create_app(access_code="purple-otter-42", web_dir=tmp_path))
    assert c.get("/api/health").json()["access_code_required"] is True
    assert c.get("/").status_code == 200
    for headers in ({}, {"x-ringtail-access-code": "wrong"}, {"x-ringtail-access-code": "purple-otter-4"}):
        r = c.post("/api/prompt", json=REQ, headers=headers)
        assert r.status_code == 401 and "access code" in r.json()["error"]
        assert "purple" not in r.text
    ok = c.post("/api/prompt", json=REQ, headers={"x-ringtail-access-code": "purple-otter-42"})
    assert ok.status_code == 200
    assert "purple" not in c.get("/api/health").text


def test_wrong_codes_use_up_the_rate_limit(tmp_path):
    c = TestClient(create_app(access_code="purple-otter-42", rate_per_minute=3, web_dir=tmp_path))
    codes = [c.post("/api/prompt", json=REQ, headers={"x-ringtail-access-code": f"guess{i}"}).status_code
             for i in range(4)]
    assert codes == [401, 401, 401, 429]


def test_busy_server_refuses_instead_of_queueing(tmp_path):
    c = TestClient(create_app(max_concurrent=0, web_dir=tmp_path))
    r = c.post("/api/check", json={"draft": GOOD_DRAFT})
    assert r.status_code == 503 and r.headers["retry-after"] == "5"
    assert c.get("/api/health").status_code == 200


def test_privacy_page_is_served_with_the_security_headers():
    from backend.app import WEB_DIR
    c = TestClient(create_app(web_dir=WEB_DIR))
    r = c.get("/privacy.html")
    assert r.status_code == 200
    assert "never reaches the Ringtail server" in r.text
    assert r.headers["content-security-policy"] == CSP
