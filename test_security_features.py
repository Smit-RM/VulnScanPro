"""
Security-feature unit/integration tests (pytest, Flask test client).
=====================================================================
These run WITHOUT a live server and WITHOUT touching the network:

  * Auth flows use the in-process Flask test client against an isolated,
    throwaway SQLite database.
  * Scanner checks (XSS / SQLi / CSRF) run against stubbed HTTP responses,
    so no real target is ever contacted.

Covered (as requested):
  1. Account lockout after N consecutive failed logins
  2. JWT expiry behaviour (expired token rejected, valid token accepted)
  3. XSS check rejects HTML-encoded reflections (false-positive guard)
  4. SQL-injection check matches real DB error patterns
  5. CSRF check flags a POST form that carries no anti-CSRF token

Run with:  pytest
(For the old live-server smoke script see integration_smoke_test.py.)
"""

import os
import tempfile
import uuid
from datetime import timedelta

# ---------------------------------------------------------------------------
# Point the app at an isolated throwaway DB BEFORE importing it. The app's own
# .env loader does NOT define DATABASE_URL, so this value survives that loader.
# ---------------------------------------------------------------------------
_TMP_DB = os.path.join(tempfile.gettempdir(), f"vulnscan_test_{uuid.uuid4().hex}.db")
os.environ["DATABASE_URL"] = "sqlite:///" + _TMP_DB.replace("\\", "/")
os.environ["REQUIRE_EMAIL_VERIFICATION"] = "0"

import pytest
import backend_app as bapp


# ============================ FIXTURES ============================

@pytest.fixture(scope="session", autouse=True)
def _schema():
    """Create the schema once in the throwaway DB, drop it at the end."""
    with bapp.app.app_context():
        bapp.db.drop_all()
        bapp.db.create_all()
    yield
    with bapp.app.app_context():
        bapp.db.drop_all()
    try:
        os.remove(_TMP_DB)
    except OSError:
        pass


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Make every test hermetic and fast:

      * no outbound email  (lockout/verification emails would hit real Gmail
        with the credentials in .env — patched to no-ops here)
      * no cooperative sleep (progressive login delay -> 0)
      * IP rate limiter effectively disabled so it can't mask functional results
      * throttle/lockout state and the user table reset to a clean slate
    """
    monkeypatch.setattr(bapp, "_send_lockout_email", lambda *a, **k: None)
    monkeypatch.setattr(bapp, "_send_verification_email", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(bapp.eventlet, "sleep", lambda *a, **k: None)
    monkeypatch.setattr(bapp, "SMTP_HOST", None)
    monkeypatch.setattr(bapp, "RL_MAX", 10_000)      # don't let 429s interfere
    monkeypatch.setattr(bapp, "DELAY_BASE", 0.0)
    monkeypatch.setattr(bapp, "DELAY_JITTER", 0.0)

    bapp._IP_HITS.clear()
    bapp._IP_FAILS.clear()
    bapp._ACCTS.clear()

    with bapp.app.app_context():
        bapp.db.session.query(bapp.User).delete()
        bapp.db.session.commit()
    yield


@pytest.fixture()
def client():
    return bapp.app.test_client()


def make_user(username, password, **kwargs):
    """Create a verified, active user directly in the DB (bypasses the email flow)."""
    with bapp.app.app_context():
        u = bapp.User(username=username, email=f"{username}@example.com",
                      email_verified=True, **kwargs)
        u.set_password(password)
        bapp.db.session.add(u)
        bapp.db.session.commit()
        return u.id


class FakeResponse:
    """Minimal stand-in for a requests.Response used to stub scanner HTTP calls."""
    def __init__(self, text="", headers=None, status_code=200):
        self.text = text
        self.headers = headers or {}
        self.status_code = status_code


def make_scanner():
    return bapp.VulnerabilityScanner("test-scan", "http://testserver", {}, None)


# ==================== 1. ACCOUNT LOCKOUT ====================

def test_account_lockout_after_n_failures(client):
    """After LOCK_THRESHOLD consecutive failures the account is locked, and even
    the CORRECT password is rejected — without the response revealing the lock."""
    make_user("lockvictim", "CorrectPass1")

    # Control: correct credentials work normally (also proves creds are valid).
    ok = client.post("/api/auth/login",
                     json={"username": "lockvictim", "password": "CorrectPass1"})
    assert ok.status_code == 200
    assert ok.get_json().get("token")

    # Drive LOCK_THRESHOLD consecutive failures.
    for i in range(bapp.LOCK_THRESHOLD):
        r = client.post("/api/auth/login",
                        json={"username": "lockvictim", "password": "WrongPass9"})
        assert r.status_code == 401, f"attempt {i+1} expected 401, got {r.status_code}"

    # Now locked: the correct password must STILL be rejected.
    locked = client.post("/api/auth/login",
                         json={"username": "lockvictim", "password": "CorrectPass1"})
    assert locked.status_code == 401, "correct password should be rejected while locked"
    body = locked.get_json()
    assert "token" not in body
    # The failure is indistinguishable — it must not disclose the lockout.
    assert not any(w in body.get("error", "").lower()
                   for w in ("lock", "too many", "attempts", "blocked")), body


# ==================== 2. JWT EXPIRY ====================

def test_expired_jwt_is_rejected(client):
    """An access token past its expiry is rejected (401) on a protected route."""
    uid = make_user("jwtuser", "SomePass123")
    with bapp.app.app_context():
        expired = bapp.create_access_token(
            identity=uid, expires_delta=timedelta(seconds=-1))
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401


def test_valid_jwt_is_accepted(client):
    """A freshly minted, unexpired token is accepted on the same route."""
    uid = make_user("jwtuser2", "SomePass123")
    with bapp.app.app_context():
        good = bapp.create_access_token(identity=uid)
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {good}"})
    assert r.status_code == 200
    assert r.get_json()["user"]["username"] == "jwtuser2"


def test_protected_route_requires_token(client):
    """No token at all -> 401 (guards against the expiry test passing trivially)."""
    r = client.get("/api/auth/me")
    assert r.status_code == 401


# ==================== 3. XSS FALSE-POSITIVE GUARD ====================

def test_xss_ignores_html_encoded_reflection():
    """An HTML-entity-encoded reflection (&lt;script&gt;...) is NOT a vulnerability
    and must not be flagged."""
    s = make_scanner()
    payload = s.XSS_PAYLOADS[0]          # '<script>alert("XSS")</script>'
    encoded = (payload.replace("&", "&amp;").replace("<", "&lt;")
                      .replace(">", "&gt;").replace('"', "&quot;"))
    s.session.get = lambda u, **k: FakeResponse(
        text=f"<html>You searched for: {encoded}</html>",
        headers={"Content-Type": "text/html; charset=utf-8"})
    assert s.check_xss("http://testserver/search?q=hi") == []


def test_xss_flags_raw_unencoded_reflection():
    """A raw, unencoded reflection of the payload IS flagged (proves the guard
    above is discriminating, not just always-negative)."""
    s = make_scanner()
    payload = s.XSS_PAYLOADS[0]
    s.session.get = lambda u, **k: FakeResponse(
        text=f"<html>You searched for: {payload}</html>",
        headers={"Content-Type": "text/html; charset=utf-8"})
    findings = s.check_xss("http://testserver/search?q=hi")
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "xss"


def test_xss_skips_json_responses():
    """A reflected payload in a JSON (non-HTML) response won't execute -> not flagged."""
    s = make_scanner()
    payload = s.XSS_PAYLOADS[0]
    s.session.get = lambda u, **k: FakeResponse(
        text=f'{{"q": "{payload}"}}',
        headers={"Content-Type": "application/json"})
    assert s.check_xss("http://testserver/api/search?q=hi") == []


# ==================== 4. SQLi ERROR-PATTERN MATCH ====================

def test_sqli_flags_real_error_pattern():
    """A response body containing a genuine DB error signature is flagged critical."""
    s = make_scanner()
    s.session.get = lambda u, **k: FakeResponse(
        text="Warning: You have an error in your SQL syntax; "
             "check the manual that corresponds to your MySQL server version")
    findings = s.check_sql_injection("http://testserver/item?id=1")
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "sql_injection"
    assert findings[0]["severity"] == "critical"


def test_sqli_ignores_clean_response():
    """A benign body with no DB error signature is NOT flagged."""
    s = make_scanner()
    s.session.get = lambda u, **k: FakeResponse(
        text="<html><body>Item #1 — In stock</body></html>")
    assert s.check_sql_injection("http://testserver/item?id=1") == []


# ==================== 5. CSRF TOKEN-PRESENCE CHECK ====================

def test_csrf_flags_post_form_without_token():
    """A POST form with no csrf/token field is flagged."""
    s = make_scanner()
    form = {"method": "post", "url": "http://testserver/transfer",
            "inputs": [{"name": "amount", "type": "text"},
                       {"name": "to", "type": "text"}]}
    findings = s.check_csrf("http://testserver/transfer", form)
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "csrf"


def test_csrf_ok_when_token_present():
    """A POST form that includes a csrf token field is NOT flagged."""
    s = make_scanner()
    form = {"method": "post", "url": "http://testserver/transfer",
            "inputs": [{"name": "amount", "type": "text"},
                       {"name": "csrf_token", "type": "hidden"}]}
    assert s.check_csrf("http://testserver/transfer", form) == []


def test_csrf_ignores_get_forms():
    """GET forms are not state-changing -> not flagged for missing CSRF token."""
    s = make_scanner()
    form = {"method": "get", "url": "http://testserver/search",
            "inputs": [{"name": "q", "type": "text"}]}
    assert s.check_csrf("http://testserver/search", form) == []


# ==================== 6. SSRF EVIDENCE DISCIPLINE ====================

def test_ssrf_no_candidate_params():
    """A non-URL param with an unrelated name is not even a candidate -> no probing."""
    s = make_scanner()
    assert s.check_ssrf("http://testserver/page?q=hello") == []


def test_ssrf_flags_metadata_reflection():
    """Reflecting cloud-metadata content back is confirmed SSRF (critical)."""
    s = make_scanner()
    body = "ami-id\ninstance-id\ninstance-type\nlocal-ipv4\nsecurity-credentials\n"
    s.session.get = lambda u, **k: FakeResponse(status_code=200, text=body)
    findings = s.check_ssrf("http://testserver/fetch?url=http://example.com")
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "ssrf"
    assert findings[0]["severity"] == "critical"


def test_ssrf_flags_redirect_to_internal():
    """A 3xx Location pointing at an internal address is confirmed SSRF (high)."""
    s = make_scanner()
    s.session.get = lambda u, **k: FakeResponse(
        status_code=302, headers={"Location": "http://169.254.169.254/"})
    findings = s.check_ssrf("http://testserver/fetch?url=http://example.com")
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "ssrf"
    assert "169.254.169.254" in findings[0]["evidence"]


def test_ssrf_ignores_benign_candidate():
    """A candidate param the server simply reflects/ignores (no metadata, no
    redirect, no timing gap) is NOT flagged — the false-positive guard."""
    s = make_scanner()
    s.session.get = lambda u, **k: FakeResponse(status_code=200, text="<html>ok</html>")
    assert s.check_ssrf("http://testserver/fetch?url=http://example.com") == []


def test_ssrf_metadata_needs_two_markers():
    """A single coincidental metadata-ish word is NOT enough to flag."""
    s = make_scanner()
    s.session.get = lambda u, **k: FakeResponse(
        status_code=200, text="<html>Our placement policy is here</html>")
    assert s.check_ssrf("http://testserver/fetch?url=http://example.com") == []


# ==================== 7. ACTIVE IDOR TESTING ====================

def make_idor_scanner():
    """Scanner with a secondary identity; returns (scanner, secondary_session)."""
    s = bapp.VulnerabilityScanner(
        "idor-scan", "http://testserver",
        {"auth_secondary": {"mode": "bearer", "value": "identity-B-token"}}, None)
    sec = s._get_secondary_session()   # build + cache the B session
    return s, sec


def test_idor_skips_without_secondary_credential():
    """No auth_secondary configured -> skip gracefully (no error, no finding)."""
    s = make_scanner()   # config == {}
    assert s.check_idor("http://testserver/api/projects/42") == []


def test_idor_skips_when_no_object_id_in_path():
    """A path with no numeric/UUID id is not an object reference."""
    s, _ = make_idor_scanner()
    assert s.check_idor("http://testserver/api/dashboard/stats") == []


def test_idor_flagged_when_b_reads_a_object(monkeypatch):
    """B is served A's object (200) but denied a non-owned probe id (404) -> IDOR."""
    s, sec = make_idor_scanner()
    s.session.get = lambda u, **k: FakeResponse(status_code=200, text="secret-of-42")

    def b_get(u, **k):
        # B can read /42 (the IDOR) but a random non-owned id returns 404.
        if u.rstrip("/").endswith("/42"):
            return FakeResponse(status_code=200, text="secret-of-42")
        return FakeResponse(status_code=404, text="not found")
    sec.get = b_get

    findings = s.check_idor("http://testserver/api/projects/42")
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "idor"
    assert findings[0]["severity"] == "high"


def test_idor_not_flagged_when_b_is_denied(monkeypatch):
    """Proper access control: B is denied the target (403) -> no finding."""
    s, sec = make_idor_scanner()
    s.session.get = lambda u, **k: FakeResponse(status_code=200, text="secret-of-42")
    sec.get = lambda u, **k: FakeResponse(status_code=403, text="forbidden")
    assert s.check_idor("http://testserver/api/projects/42") == []


def test_idor_not_flagged_for_public_endpoint(monkeypatch):
    """No object-level authz at all (probe id ALSO returns 200) -> not IDOR."""
    s, sec = make_idor_scanner()
    s.session.get = lambda u, **k: FakeResponse(status_code=200, text="page")
    sec.get = lambda u, **k: FakeResponse(status_code=200, text="page")
    assert s.check_idor("http://testserver/api/projects/42") == []


def test_idor_supports_uuid_ids(monkeypatch):
    """UUID object ids are recognised and tested the same way."""
    s, sec = make_idor_scanner()
    uid = "11111111-2222-3333-4444-555555555555"
    s.session.get = lambda u, **k: FakeResponse(status_code=200, text="uuid-secret")

    def b_get(u, **k):
        return (FakeResponse(status_code=200, text="uuid-secret")
                if uid in u else FakeResponse(status_code=404, text="nope"))
    sec.get = b_get

    findings = s.check_idor(f"http://testserver/api/users/{uid}")
    assert len(findings) == 1
    assert findings[0]["vuln_type"] == "idor"
