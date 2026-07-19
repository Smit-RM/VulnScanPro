"""
Smart Web Application Vulnerability Scanner - Backend API
Flask + SQLAlchemy + JWT + WebSockets
"""
from flask_socketio import emit, join_room
import zap_service
from pydantic import BaseModel, field_validator, ValidationError
import logging
import html
import re
from bs4 import BeautifulSoup
import requests
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask import Flask, request, jsonify, g
from functools import wraps
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
from email.message import EmailMessage
import os
import json
import time
import uuid
import hashlib
import threading
import sqlite3
import math
import random
import secrets
import smtplib
import eventlet
from dotenv import load_dotenv
load_dotenv()

# Configure logging
# Try to load .env file manually from the app's directory before environment variables are read
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
if os.path.exists(_env_path):
    try:
        with open(_env_path, 'r', encoding='utf-8') as _env_file:
            for _line in _env_file:
                _line = _line.strip()
                if not _line or _line.startswith('#'):
                    continue
                if '=' in _line:
                    _k, _v = _line.split('=', 1)
                    os.environ[_k.strip()] = _v.strip().strip("'\"")
    except Exception as _e:
        print(f"Error loading .env file: {_e}")

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY', 'vuln-scanner-secret-key-2024')
app.config['JWT_SECRET_KEY'] = os.environ.get(
    'JWT_SECRET_KEY', 'jwt-secret-2024')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)
# Pin the SQLite DB to one ABSOLUTE path next to this file (in ./instance) so the
# server and any helper scripts always open the IDENTICAL file. A relative URI like
# 'sqlite:///vulnscanner.db' is resolved against each process's working directory
# (and Flask's instance folder), which silently splits data across multiple files.
_DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'instance', 'vulnscanner.db')
os.makedirs(os.path.dirname(_DEFAULT_DB_PATH), exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///' + _DEFAULT_DB_PATH.replace('\\', '/'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
logger.info("Using database: %s", app.config['SQLALCHEMY_DATABASE_URI'])

# Refuse to run with the built-in default secrets in production — those literals
# are public, and a known JWT_SECRET_KEY lets anyone forge access tokens for any
# user (and forge the lockout reset tokens minted below). Warn loudly in dev.
_DEFAULT_SECRETS = {
    'SECRET_KEY': 'vuln-scanner-secret-key-2024',
    'JWT_SECRET_KEY': 'jwt-secret-2024',
}
_IS_PRODUCTION = 'production' in (
    os.environ.get('FLASK_ENV', '') + os.environ.get('APP_ENV', '')).lower()
for _key, _default in _DEFAULT_SECRETS.items():
    if app.config.get(_key) == _default:
        if _IS_PRODUCTION:
            raise RuntimeError(
                f"{_key} must be set to a strong non-default value in production")
        logger.warning(
            "%s is using the built-in default value — set a strong %s before deploying.",
            _key, _key)

# Lock CORS to explicit origins — never use "*" in production.
# Override with a comma-separated CORS_ORIGINS env var.
_ALLOWED_ORIGINS = [
    o.strip() for o in
    os.environ.get(
        'CORS_ORIGINS',
        'http://127.0.0.1:5000,http://localhost:5000'
    ).split(',')
    if o.strip()
]
CORS(app, origins=_ALLOWED_ORIGINS, supports_credentials=False)
db = SQLAlchemy(app)
jwt = JWTManager(app)
# Password hashing policy: bcrypt with a work factor >= 12 (OWASP floor). This is
# set in app.config BEFORE Bcrypt(app) so flask-bcrypt reads it at init time.
# Override with the BCRYPT_LOG_ROUNDS env var, but the floor of 12 is enforced.
try:
    BCRYPT_ROUNDS = max(12, int(os.environ.get('BCRYPT_LOG_ROUNDS', '12')))
except (TypeError, ValueError):
    BCRYPT_ROUNDS = 12
app.config['BCRYPT_LOG_ROUNDS'] = BCRYPT_ROUNDS
bcrypt = Bcrypt(app)

# ---- Async task backend: Celery + Redis, with a graceful threading fallback ----
# When REDIS_URL is set (and celery/redis are importable), scans run in a Celery
# worker and Socket.IO progress is relayed across processes through a Redis message
# queue. When REDIS_URL is UNSET, the app runs entirely in-process using one
# background thread per scan — zero extra infrastructure, so local dev/demo works
# with no Redis and no worker. See dispatch_scan() / run_scan_task().
REDIS_URL = os.environ.get('REDIS_URL')
celery_app = None
_CELERY_ENABLED = False
_SIO_MESSAGE_QUEUE = None
if REDIS_URL:
    try:
        import redis as _redis_pkg  # noqa: F401 — ensure the client lib is present
        from celery import Celery
        celery_app = Celery('vulnscan', broker=REDIS_URL, backend=REDIS_URL)
        celery_app.conf.update(task_serializer='json', accept_content=['json'],
                               result_serializer='json', timezone='UTC')
        _CELERY_ENABLED = True
        _SIO_MESSAGE_QUEUE = REDIS_URL
        logger.info(
            "Celery + Redis task backend enabled (broker=%s)", REDIS_URL)
    except Exception as _e:
        logger.warning(
            "REDIS_URL set but Celery/redis unavailable (%s); using threading fallback",
            _e)

# The web Socket.IO server joins the same Redis message queue when configured, so it
# can deliver progress events that the Celery worker publishes from another process.
_sio_kwargs = dict(cors_allowed_origins=_ALLOWED_ORIGINS,
                   async_mode='eventlet')
if _SIO_MESSAGE_QUEUE:
    _sio_kwargs['message_queue'] = _SIO_MESSAGE_QUEUE
socketio = SocketIO(app, **_sio_kwargs)


@app.before_request
def check_user_active():
    # Only run this check for API requests, ignoring static files, root page, login/register
    if request.path in ['/api/auth/login', '/api/auth/register', '/']:
        return
    if not request.path.startswith('/api/'):
        return
    if request.method == 'OPTIONS':
        return

    # Verify if there is a JWT token in the request headers
    from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        if user_id:
            user = User.query.get(user_id)
            if user and not user.is_active:
                return jsonify({'error': 'Your account has been temporarily disabled.'}), 403
    except Exception:
        # Ignore JWT verification errors here; standard @jwt_required() decorators on the endpoints will raise them.
        pass


# ============ SECURITY RESPONSE HEADERS ============
# Practice what the scanner preaches: set the same headers on our OWN responses
# that VulnerabilityScanner.check_security_headers flags as missing on other
# sites. An after_request hook applies them uniformly to API JSON, the served
# frontend, static assets, and error responses.
#
#   - WebSocket safety: with async_mode='eventlet', the Socket.IO handshake and
#     traffic are served by the Engine.IO WSGI middleware wrapping Flask, so
#     /socket.io/ requests never reach this hook — the real-time connection is
#     untouched. "connect-src 'self'" still permits the same-origin WebSocket
#     (CSP3) and the client's XHR-polling fallback, so live updates keep working.
#   - CORS safety: flask-cors sets its Access-Control-* headers in its own
#     after_request handler; this hook only ADDS the headers below (via
#     setdefault) and never overwrites CORS or anything an endpoint already set.
#   - The bundled frontend needs a few explicit CSP allowances (see inline notes):
#     inline on* handlers + style="" attributes ('unsafe-inline'), the Socket.IO
#     client loaded from cdn.socket.io, and Google Fonts. No eval() is used, so
#     'unsafe-eval' is deliberately NOT granted. Everything else is locked to self.
_CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.socket.io; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' data: https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self' https://api.osv.dev https://access.redhat.com https://api.ipify.org https://api.my-ip.io https://ipapi.co https://free.freeipapi.com https://api.ip.sb https://api.pwnedpasswords.com https://cloudflare-dns.com https://api.certspotter.com; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "object-src 'none'"
)


@app.after_request
def add_security_headers(response):
    """Set standard security response headers on every response.

    Uses setdefault so a route that intentionally sets its own value (e.g. a
    looser X-Frame-Options for an embeddable widget) is never clobbered.
    """
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    # Browsers only honor HSTS over HTTPS (silently ignored on plain-HTTP dev),
    # but advertising it on every response covers any HTTPS deployment.
    response.headers.setdefault(
        'Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    response.headers.setdefault('Content-Security-Policy', _CSP_POLICY)
    response.headers.setdefault(
        'Referrer-Policy', 'strict-origin-when-cross-origin')
    # Modern OWASP guidance: disable the legacy browser XSS auditor (it caused its
    # own vulns and is removed from current browsers). "0" satisfies the app's own
    # check_security_headers presence check while relying on CSP for real defense.
    response.headers.setdefault('X-XSS-Protection', '0')
    return response

# ============ LOGIN THROTTLE / ACCOUNT LOCKOUT ============
# Brute-force defenses for /api/auth/login:
#   - IP rate limit: max 10 requests / IP / minute (sliding window) -> 429
#   - Account lockout: 15 min lock after 5 consecutive failed attempts
#   - Progressive delay: each failed attempt from a source IP sleeps longer
#   - State kept in a thread-safe in-memory cache (single-process app; swap the
#     _ACCTS / _IP_HITS / _IP_FAILS dicts for Redis if you scale horizontally)
#   - On the locking transition, the user is emailed a password-reset link (once)
#   - Locked vs wrong-password is INDISTINGUISHABLE in both body and timing
#
# eventlet notes (async_mode='eventlet', NO eventlet.monkey_patch()):
#   - The progressive delay uses eventlet.sleep() (cooperative) — a blocking
#     time.sleep() would freeze the whole hub.
#   - _THROTTLE_LOCK is only ever held for O(1) dict mutations, never across a
#     sleep / bcrypt / DB / SMTP call.
#   - bcrypt and the SQLite query are blocking native calls that do NOT yield to
#     the hub; that is a pre-existing property of this app (every login already
#     paid it). The 10/IP/min gate bounds how often the added equalization bcrypt
#     runs. For heavy concurrent load, call eventlet.monkey_patch() at process
#     start (or move bcrypt/DB onto eventlet.tpool) — out of scope for this change.
#   - The lockout email is dispatched on a REAL OS thread (not a greenlet), so the
#     blocking smtplib call can never stall the hub or perturb response timing.


def _int_env(key, default):
    """Parse an int env override, falling back to the default on bad/empty input
    so one typo'd tuning knob can't crash module import."""
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        logger.warning("invalid %s; using default %s", key, default)
        return default


def _float_env(key, default):
    try:
        return float(os.environ.get(key, default))
    except (TypeError, ValueError):
        logger.warning("invalid %s; using default %s", key, default)
        return default


# ---- Config (all env-overridable) ----
RL_MAX = _int_env('LOGIN_RL_MAX', 10)                 # max attempts ...
# ... per IP per window (sec)
RL_WINDOW = _int_env('LOGIN_RL_WINDOW_SEC', 60)
# consecutive fails -> lock
LOCK_THRESHOLD = _int_env('LOGIN_LOCK_THRESHOLD', 5)
LOCK_DURATION = _int_env('LOGIN_LOCK_DURATION_SEC',
                         900)   # lock length (15 min)
DELAY_BASE = _float_env('LOGIN_DELAY_BASE_SEC', 0.25)
DELAY_CAP = _float_env('LOGIN_DELAY_CAP_SEC', 4.0)
DELAY_JITTER = _float_env('LOGIN_DELAY_JITTER_SEC', 0.10)
# reset an IP's delay streak after idle
DELAY_DECAY = _int_env('LOGIN_DELAY_DECAY_SEC', 900)
TRUST_XFF = os.environ.get('TRUST_XFF', '0') == '1'
# proxy hops we own (right side of XFF)
TRUSTED_PROXY_COUNT = _int_env('TRUSTED_PROXY_COUNT', 1)
_SWEEP_EVERY = 50          # opportunistic cleanup cadence
_ACCTS_MAX = 50_000        # hard caps bound worst-case memory use
_IP_MAX = 50_000
_DELAY_EXP_CAP = 32        # cap the 2**exp term so a huge fail count can't overflow float

# SMTP (unset today -> lockout email degrades to a logged no-op)
SMTP_HOST = os.environ.get('SMTP_HOST')        # None => email disabled
SMTP_PORT = _int_env('SMTP_PORT', 587)
SMTP_USER = os.environ.get('SMTP_USER')
SMTP_PASS = os.environ.get('SMTP_PASS')
SMTP_FROM = os.environ.get('SMTP_FROM', 'no-reply@vulnscanner.local')
SMTP_TLS = os.environ.get('SMTP_TLS', '1') != '0'
APP_BASE_URL = os.environ.get('APP_BASE_URL', 'http://127.0.0.1:5000')

# ─── ZAP Integration Configuration ───────────────────────────────────────────
# ZAP_API_URL and ZAP_API_KEY are read by zap_service lazily at call time from
# os.environ so they are NEVER hardcoded and NEVER exposed to browser clients.
# Set both in Render environment variables (or .env for local dev).
_ZAP_ENABLED = bool(os.environ.get('ZAP_API_URL'))
if _ZAP_ENABLED:
    logger.info('ZAP integration ENABLED — ZAP_API_URL is configured')
else:
    logger.info('ZAP integration DISABLED — ZAP_API_URL not set; '
                'ZAP endpoints will return 503 until configured')

# Require new users to verify their email before they can log in. Default ON; set
# REQUIRE_EMAIL_VERIFICATION=0 to disable (e.g. local testing without SMTP).
REQUIRE_EMAIL_VERIFICATION = os.environ.get(
    'REQUIRE_EMAIL_VERIFICATION', '1') != '0'

# Constant-time dummy hash (same bcrypt cost as real hashes) — lets the no-user
# and malformed-input branches burn the same CPU as a real password check, so
# they aren't a faster (distinguishable) path.
_DUMMY_HASH = bcrypt.generate_password_hash(
    secrets.token_hex(16)).decode('utf-8')

# Stateless, signed, expiring reset token — needs no DB column, survives restart.
_reset_serializer = URLSafeTimedSerializer(
    app.config['SECRET_KEY'], salt='pw-reset')
_verify_serializer = URLSafeTimedSerializer(
    app.config['SECRET_KEY'], salt='email-verify')

# ---- Thread-safe in-memory store ----
# One coarse lock guards the dicts; it is only ever held for O(1) dict mutations,
# never across a sleep / bcrypt / DB / SMTP call.
_THROTTLE_LOCK = threading.Lock()
_call_counter = 0
# ip -> list[monotonic timestamps]   (drives the 10/min rate limit)
_IP_HITS = {}
# ip -> [consecutive_fail_count, last_seen]  (drives the progressive delay)
_IP_FAILS = {}


class _AcctState:
    __slots__ = ('fails', 'locked_until', 'lock_emailed', 'last_seen')

    def __init__(self):
        self.fails = 0
        self.locked_until = 0.0    # monotonic deadline; 0.0 == not locked
        self.lock_emailed = False  # idempotency latch for the current lock episode
        self.last_seen = 0.0


_ACCTS = {}          # username -> _AcctState


def _client_ip():
    """Best-effort client IP. Only consult X-Forwarded-For when TRUST_XFF=1 (i.e. we
    sit behind a proxy WE control), and then read from the RIGHT, skipping the proxy
    hops we own — the leftmost XFF value is attacker-supplied and must never be trusted."""
    if TRUST_XFF:
        xff = request.headers.get('X-Forwarded-For', '')
        parts = [p.strip() for p in xff.split(',') if p.strip()]
        if parts:
            idx = len(parts) - 1 - TRUSTED_PROXY_COUNT
            if 0 <= idx < len(parts):
                return parts[idx]
    return request.remote_addr or 'unknown'


def _maybe_sweep(now):
    """Opportunistic cleanup. MUST be called while holding _THROTTLE_LOCK."""
    global _call_counter
    _call_counter += 1
    if _call_counter % _SWEEP_EVERY != 0:
        return
    cutoff = now - RL_WINDOW
    for ip in list(_IP_HITS.keys()):
        hits = _IP_HITS[ip]
        hits[:] = [t for t in hits if t > cutoff]
        if not hits:
            del _IP_HITS[ip]
    for ip in list(_IP_FAILS.keys()):
        if (now - _IP_FAILS[ip][1]) > DELAY_DECAY:
            del _IP_FAILS[ip]
    for u in list(_ACCTS.keys()):
        s = _ACCTS[u]
        if s.locked_until <= now and s.fails == 0 and (now - s.last_seen) > 3600:
            del _ACCTS[u]
    # Hard caps — last-resort eviction of the stalest entries, even locked ones, so a
    # flood of distinct usernames/IPs can't grow these dicts without bound. An evicted
    # lock simply re-locks on the attacker's next attempt; bounded memory wins.
    if len(_ACCTS) > _ACCTS_MAX:
        victims = sorted((s.last_seen, u) for u, s in _ACCTS.items())
        for _, u in victims[:len(_ACCTS) - _ACCTS_MAX]:
            del _ACCTS[u]
    if len(_IP_HITS) > _IP_MAX:
        victims = sorted(_IP_HITS.items(),
                         key=lambda kv: kv[1][-1] if kv[1] else 0)
        for ip, _ in victims[:len(_IP_HITS) - _IP_MAX]:
            del _IP_HITS[ip]
    if len(_IP_FAILS) > _IP_MAX:
        victims = sorted(_IP_FAILS.items(), key=lambda kv: kv[1][1])
        for ip, _ in victims[:len(_IP_FAILS) - _IP_MAX]:
            del _IP_FAILS[ip]


def rate_limit_login(fn):
    """Sliding-window IP rate limit. Runs before any account logic, so a flood is
    cheap and the 429 leaks nothing about account existence/lockout (it keys on IP
    volume only). This 429 is the one response allowed to be distinguishable."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        ip = _client_ip()
        now = time.monotonic()
        with _THROTTLE_LOCK:
            _maybe_sweep(now)
            hits = _IP_HITS.setdefault(ip, [])
            cutoff = now - RL_WINDOW
            hits[:] = [t for t in hits if t > cutoff]
            if len(hits) >= RL_MAX:
                retry_after = max(1, math.ceil(hits[0] + RL_WINDOW - now))
                over_limit = True
            else:
                hits.append(now)
                over_limit = False
        if over_limit:
            logger.warning("login rate-limited ip=%s (>%s/%ss)",
                           ip, RL_MAX, RL_WINDOW)
            try:
                db.session.add(AuditLog(event_type='rate_limit', ip_address=ip,
                                        details=f'IP rate limited after {RL_MAX} requests in {RL_WINDOW}s'))
                db.session.commit()
            except Exception as _e:
                logger.error("Failed to write rate_limit audit log: %s", _e)
                db.session.rollback()
            resp = jsonify(
                {'error': 'Too many requests. Please try again later.'})
            resp.headers['Retry-After'] = str(retry_after)
            return resp, 429
        return fn(*args, **kwargs)
    return wrapper


def _delay_for(n):
    """Progressive delay (seconds) for the n-th consecutive failure (n>=1):
    0.25, 0.5, 1, 2, 4, 4, ... capped, plus jitter. The exponent is capped so a very
    large fail count can't raise OverflowError before min() clamps it."""
    exp = min(max(0, n - 1), _DELAY_EXP_CAP)
    base = min(DELAY_CAP, DELAY_BASE * (2 ** exp))
    return base + random.uniform(0.0, DELAY_JITTER)


def _record_ip_failure(ip):
    """Track consecutive failures per SOURCE IP and return the new count. The
    progressive delay is keyed on this (the requester's own behaviour) rather than on
    the target account's failure count — so a probe's latency can't reveal whether the
    target account is locked, keeping locked vs wrong-password indistinguishable."""
    now = time.monotonic()
    with _THROTTLE_LOCK:
        rec = _IP_FAILS.get(ip)
        if rec is None or (now - rec[1]) > DELAY_DECAY:   # decay an idle streak
            rec = [0, now]
            _IP_FAILS[ip] = rec
        rec[0] += 1
        rec[1] = now
        return rec[0]


def _reset_ip_failures(ip):
    """Clear an IP's delay streak after a successful login from that IP."""
    with _THROTTLE_LOCK:
        _IP_FAILS.pop(ip, None)


def _try_admit(username):
    """Atomic admission check (under the lock). Returns True — and clears ALL
    failure/lock state for the account — only if the account is not currently locked.
    A correct password against a locked account returns False (lockout takes
    precedence), with no read-then-act race against a concurrent locking transition."""
    now = time.monotonic()
    with _THROTTLE_LOCK:
        s = _ACCTS.get(username)
        if s and s.locked_until and now >= s.locked_until:   # lock expired -> reset
            s.fails = 0
            s.locked_until = 0.0
            s.lock_emailed = False
        if s and s.locked_until > now:
            return False
        _ACCTS.pop(username, None)
        return True


def _record_failure(username, ip):
    """Record a failed attempt for the account (under the lock). Applies the lock on
    the 5th consecutive failure and reports whether THIS attempt is the locking
    transition that should send the email. Returns should_email (bool)."""
    now = time.monotonic()
    with _THROTTLE_LOCK:
        s = _ACCTS.get(username)
        if s is None:
            s = _AcctState()
            _ACCTS[username] = s
        if s.locked_until and now >= s.locked_until:     # normalize an expired lock first
            s.fails = 0
            s.locked_until = 0.0
            s.lock_emailed = False
        s.fails += 1
        s.last_seen = now
        should_email = False
        if s.fails >= LOCK_THRESHOLD and s.locked_until <= now:   # locking transition
            s.locked_until = now + LOCK_DURATION                  # set once; never extended
            should_email = not s.lock_emailed
            s.lock_emailed = True
            logger.warning("account locked username=%s ip=%s fail_count=%s",
                           username, ip, s.fails)
    return should_email


def _login_reject(password, delay, did_bcrypt):
    """Shared rejection tail for EVERY failed login (wrong password, unknown user,
    locked account, malformed body). Equalizes bcrypt cost, applies the cooperative
    progressive delay, then returns the byte-identical 401. This is what makes
    'locked' and 'wrong password' indistinguishable in body and timing."""
    if not did_bcrypt:
        bcrypt.check_password_hash(
            _DUMMY_HASH, password or '')   # burn equivalent CPU
    # cooperative; outside the lock
    eventlet.sleep(delay)
    # Single generic message for EVERY failure cause (wrong password, unknown
    # user, locked account, malformed body) — never reveals which, and never
    # discloses the lockout. Same status + body + timing for all.
    return jsonify({'error': 'Incorrect email or password'}), 401


def _send_lockout_email(user_id):
    """Best-effort lockout notification with a password-reset link. Runs on a REAL OS
    thread (dispatched after the response timing is fixed), so the blocking smtplib
    call can never stall the eventlet hub or perturb login latency. Degrades to a
    logged no-op when SMTP is unconfigured. Never raises."""
    with app.app_context():
        try:
            user = User.query.get(user_id)
            if user is None:
                return
            # Bind the token to a fingerprint of the current password hash so it
            # auto-invalidates after a password change; the (future) /reset consumer
            # MUST verify both pwv and loads(token, max_age=3600) for single-use+expiry.
            pwv = hashlib.sha256(user.password_hash.encode()).hexdigest()[:16]
            token = _reset_serializer.dumps({'uid': user.id, 'pwv': pwv})
            link = f"{APP_BASE_URL}/reset?token={token}"
            if not SMTP_HOST:
                logger.info(
                    "lockout email skipped (SMTP unconfigured) uid=%s", user_id)
                logger.debug(
                    "dev reset link generated uid=%s (token suppressed)", user_id)
                return
            msg = EmailMessage()
            msg['Subject'] = 'Your account has been temporarily locked'
            msg['From'] = SMTP_FROM
            msg['To'] = user.email
            msg.set_content(
                "We locked your account for 15 minutes after several failed sign-in "
                "attempts.\n\nIf this was you, you can wait and try again, or reset your "
                f"password now (link valid for 1 hour):\n{link}\n\n"
                "If this wasn't you, please reset your password immediately.")
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as smtp:
                if SMTP_TLS:
                    smtp.starttls()
                if SMTP_USER:
                    smtp.login(SMTP_USER, SMTP_PASS)
                smtp.send_message(msg)
            logger.info("lockout email sent uid=%s", user_id)
        except Exception as e:
            logger.error("lockout email send failed uid=%s err=%s", user_id, e)


def _verification_link(user_id):
    """Build a signed email-verification URL for the given user id. Shared by the
    email sender and the register/resend handlers (so a dev with no SMTP can still
    reach the link). The token is consumed by verify_email() with a 1-hour max_age."""
    token = _verify_serializer.dumps({'uid': user_id})
    return f"{APP_BASE_URL}/api/auth/verify-email?token={token}"


def _send_verification_email(user_id):
    """Send email verification link to the registered user."""
    with app.app_context():
        try:
            user = User.query.get(user_id)
            if user is None:
                return
            link = _verification_link(user.id)
            logger.info(
                "Generated verification link for uid=%s: %s", user_id, link)

            if not SMTP_HOST:
                logger.info(
                    "Verification email skipped (SMTP unconfigured) uid=%s", user_id)
                return

            name = user.display_name or user.username
            msg = EmailMessage()
            msg['Subject'] = 'Verify your email address for VulnScan Pro'
            msg['From'] = SMTP_FROM
            msg['To'] = user.email
            # Plain-text fallback (shown by clients that don't render HTML).
            msg.set_content(
                f"Welcome to VulnScan Pro, {name}!\n\n"
                "Please verify your email address to activate your account by "
                "opening the link below:\n"
                f"{link}\n\n"
                "This link expires in 1 hour.\n\n"
                "If you did not register for this account, you can safely ignore this email."
            )
            # Rich HTML version with a real \"Verify My Email\" button.
            safe_name = html.escape(name)
            msg.add_alternative(f"""\
<!DOCTYPE html>
<html>
  <body style="margin:0;padding:0;background:#0f172a;font-family:Segoe UI,Arial,sans-serif;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0f172a;padding:32px 0;">
      <tr><td align="center">
        <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background:#1e293b;border-radius:12px;overflow:hidden;">
          <tr><td style="background:#2563eb;padding:24px 32px;">
            <h1 style="margin:0;color:#ffffff;font-size:20px;">🛡️ VulnScan Pro</h1>
          </td></tr>
          <tr><td style="padding:32px;">
            <p style="margin:0 0 16px;color:#e2e8f0;font-size:16px;">Hi {safe_name},</p>
            <p style="margin:0 0 24px;color:#94a3b8;font-size:14px;line-height:22px;">
              Thanks for registering. Please confirm your email address to activate
              your account. Just click the button below.
            </p>
            <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto;">
              <tr><td align="center" style="border-radius:8px;background:#2563eb;">
                <a href="{link}" target="_blank"
                   style="display:inline-block;padding:14px 32px;color:#ffffff;
                          font-size:15px;font-weight:600;text-decoration:none;border-radius:8px;">
                  ✓ Verify My Email
                </a>
              </td></tr>
            </table>
            <p style="margin:24px 0 8px;color:#64748b;font-size:12px;">
              Or copy and paste this link into your browser:
            </p>
            <p style="margin:0 0 24px;word-break:break-all;">
              <a href="{link}" style="color:#60a5fa;font-size:12px;">{link}</a>
            </p>
            <p style="margin:0;color:#64748b;font-size:12px;line-height:18px;">
              This link expires in 1 hour. If you did not create this account,
              you can safely ignore this email.
            </p>
          </td></tr>
        </table>
      </td></tr>
    </table>
  </body>
</html>""", subtype='html')
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as smtp:
                if SMTP_TLS:
                    smtp.starttls()
                if SMTP_USER:
                    smtp.login(SMTP_USER, SMTP_PASS)
                smtp.send_message(msg)
            logger.info("Verification email sent to %s", user.email)
        except Exception as e:
            logger.error(
                "Verification email send failed uid=%s err=%s", user_id, e)


def _verified_success_page(already=False):
    """Friendly confirmation page shown after the user clicks the verify link.
    Auto-redirects to the login screen after a short pause, with a manual link."""
    headline = "You're already verified" if already else "Email verified!"
    sub = ("Your account was already confirmed. Redirecting you to login…"
           if already else
           "Your email address has been confirmed. You can now log in. "
           "Redirecting you to login…")
    target = f"{APP_BASE_URL}/?verified=true"
    return f"""<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="refresh" content="3;url={target}">
    <title>Email verified - VulnScan Pro</title>
  </head>
  <body style="margin:0;font-family:Segoe UI,Arial,sans-serif;background:#0f172a;
               display:flex;align-items:center;justify-content:center;height:100vh;">
    <div style="background:#1e293b;border-radius:14px;padding:40px 48px;max-width:420px;
                text-align:center;box-shadow:0 10px 40px rgba(0,0,0,.4);">
      <div style="width:72px;height:72px;border-radius:50%;background:#16a34a;margin:0 auto 20px;
                  display:flex;align-items:center;justify-content:center;font-size:38px;color:#fff;">✓</div>
      <h1 style="margin:0 0 12px;color:#fff;font-size:22px;">{headline}</h1>
      <p style="margin:0 0 28px;color:#94a3b8;font-size:14px;line-height:22px;">{sub}</p>
      <a href="{target}"
         style="display:inline-block;padding:12px 28px;background:#2563eb;color:#fff;
                text-decoration:none;border-radius:8px;font-weight:600;font-size:14px;">
        Go to Login
      </a>
    </div>
    <script>setTimeout(function(){{window.location.href='{target}';}}, 3000);</script>
  </body>
</html>"""


# ============ DATABASE MODELS ============


# bcrypt hash format: $2a$/$2b$/$2y$ followed by a two-digit cost. Anything else
# found in password_hash is a LEGACY/weak value we accept exactly once, only to
# transparently re-hash it with bcrypt on the next successful login.
_BCRYPT_RE = re.compile(r'^\$2[aby]\$(\d{2})\$')
_HEX_MD5 = re.compile(r'^[0-9a-f]{32}$')    # unsalted MD5
_HEX_SHA1 = re.compile(r'^[0-9a-f]{40}$')   # unsalted SHA-1
_HEX_SHA256 = re.compile(r'^[0-9a-f]{64}$')  # unsalted SHA-256


def _verify_password(stored, password):
    """Verify a password against a stored hash; report whether it needs re-hashing.

    Returns ``(is_valid, needs_rehash)``. EVERY comparison is constant-time —
    flask-bcrypt and ``secrets.compare_digest`` both use a constant-time compare,
    so plain ``==`` string equality is never used on secret material. Legacy
    formats (werkzeug pbkdf2/scrypt, unsalted MD5/SHA-1/SHA-256 hex, and a
    last-resort plaintext compare) are recognised ONLY so the on-login migration
    can replace them with bcrypt; new passwords are always stored as bcrypt.
    """
    if not stored:
        return (False, False)
    password = password or ''
    # Current scheme: bcrypt. Re-hash only if the cost dropped below policy.
    m = _BCRYPT_RE.match(stored)
    if m:
        ok = bcrypt.check_password_hash(stored, password)
        return (ok, ok and int(m.group(1)) < BCRYPT_ROUNDS)
    # Legacy werkzeug hashes (pbkdf2:/scrypt:) — verify, then force an upgrade.
    if stored.startswith(('pbkdf2:', 'scrypt:')):
        try:
            from werkzeug.security import check_password_hash as _wz_check
            ok = _wz_check(stored, password)
        except Exception:
            ok = False
        return (ok, ok)
    # Legacy unsalted digests — insecure; supported only to migrate off them.
    low = stored.strip().lower()
    pw = password.encode('utf-8')
    if _HEX_MD5.match(low):
        return (secrets.compare_digest(low, hashlib.md5(pw).hexdigest()), True)
    if _HEX_SHA1.match(low):
        return (secrets.compare_digest(low, hashlib.sha1(pw).hexdigest()), True)
    if _HEX_SHA256.match(low):
        return (secrets.compare_digest(low, hashlib.sha256(pw).hexdigest()), True)
    # Last resort: the value was stored as plaintext. Constant-time compare, never ==.
    ok = secrets.compare_digest(stored, password)
    return (ok, ok)


class User(db.Model):
    id = db.Column(db.String(36), primary_key=True,
                   default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    display_name = db.Column(db.String(50))
    role = db.Column(db.String(20), default='user')  # admin, user
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    email_verified = db.Column(db.Boolean, default=False)
    # Forces a password change on the user's next login (set for the default admin).
    must_change_password = db.Column(db.Boolean, default=False)
    projects = db.relationship('Project', backref='owner', lazy=True)

    def set_password(self, password):
        # Always bcrypt at the configured cost (>= 12), with a fresh random salt.
        self.password_hash = bcrypt.generate_password_hash(
            password).decode('utf-8')

    def check_password(self, password):
        # Constant-time verify. If the stored hash is legacy/weak or below the
        # current cost, transparently re-hash to bcrypt(>=12) on this successful
        # check — the caller's commit on the login/success path persists it.
        ok, needs_rehash = _verify_password(self.password_hash, password)
        if ok and needs_rehash:
            self.set_password(password)
            logger.info("Upgraded stored password to bcrypt(cost=%d) for user id=%s",
                        BCRYPT_ROUNDS, self.id)
        return ok

    def to_dict(self):
        return {
            'id': self.id, 'username': self.username, 'email': self.email,
            'display_name': self.display_name,
            'role': self.role, 'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active,
            'email_verified': self.email_verified,
            'must_change_password': bool(self.must_change_password)
        }


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    # 'login_success', 'login_fail', 'lockout', 'rate_limit', 'validation_fail', 'user_update'
    event_type = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(80))
    ip_address = db.Column(db.String(45))
    details = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'username': self.username,
            'ip_address': self.ip_address,
            'details': self.details
        }


class Project(db.Model):
    id = db.Column(db.String(36), primary_key=True,
                   default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    user_id = db.Column(db.String(36), db.ForeignKey(
        'user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    targets = db.relationship(
        'Target', backref='project', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id, 'name': self.name, 'description': self.description,
            'user_id': self.user_id, 'created_at': self.created_at.isoformat(),
            'target_count': len(self.targets), 'scan_count': sum(len(t.scans) for t in self.targets)
        }


class Target(db.Model):
    id = db.Column(db.String(36), primary_key=True,
                   default=lambda: str(uuid.uuid4()))
    url = db.Column(db.String(500), nullable=False)
    name = db.Column(db.String(100))
    description = db.Column(db.Text)
    project_id = db.Column(db.String(36), db.ForeignKey(
        'project.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('Scan', backref='target',
                            lazy=True, cascade='all, delete-orphan')
    scheduled_scans = db.relationship('ScheduledScan', backref='target',
                                      lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id, 'url': self.url, 'name': self.name,
            'description': self.description, 'project_id': self.project_id,
            'created_at': self.created_at.isoformat(), 'scan_count': len(self.scans)
        }


class ScheduledScan(db.Model):
    id = db.Column(db.String(36), primary_key=True,
                   default=lambda: str(uuid.uuid4()))
    target_id = db.Column(db.String(36), db.ForeignKey(
        'target.id'), nullable=False)
    cron_expression = db.Column(db.String(100), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_run = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id,
            'target_id': self.target_id,
            'target_url': self.target.url if self.target else 'unknown',
            'cron_expression': self.cron_expression,
            'enabled': self.enabled,
            'created_at': self.created_at.isoformat(),
            'last_run': self.last_run.isoformat() if self.last_run else None
        }


class Scan(db.Model):
    id = db.Column(db.String(36), primary_key=True,
                   default=lambda: str(uuid.uuid4()))
    target_id = db.Column(db.String(36), db.ForeignKey(
        'target.id'), nullable=False)
    # pending, running, completed, failed
    status = db.Column(db.String(20), default='pending')
    progress = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    config = db.Column(db.Text, default='{}')  # JSON scan configuration
    total_urls = db.Column(db.Integer, default=0)
    scanned_urls = db.Column(db.Integer, default=0)
    # 'native' = VulnerabilityScanner engine; 'zap' = OWASP ZAP via Cloudflare tunnel
    scan_engine = db.Column(db.String(20), default='native')
    # Tracks the most recent ZAP spider or active-scan ID while the scan is running
    zap_scan_id = db.Column(db.String(50))
    vulnerabilities = db.relationship(
        'Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id, 'target_id': self.target_id, 'status': self.status,
            'progress': self.progress,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'config': json.loads(self.config), 'total_urls': self.total_urls,
            'scanned_urls': self.scanned_urls,
            'scan_engine': self.scan_engine or 'native',
            'zap_scan_id': self.zap_scan_id,
            'vuln_count': len(self.vulnerabilities),
            'severity_breakdown': self._severity_breakdown(),
            # Frontend compatibility mapping
            'url': self.target.url if self.target else 'unknown',
            'ts': int(self.started_at.timestamp() * 1000) if self.started_at else int(datetime.utcnow().timestamp() * 1000),
            'vulnCount': len(self.vulnerabilities),
            'profile': json.loads(self.config).get('auth', {}).get('mode', 'default') if self.config else 'default'
        }

    def _severity_breakdown(self):
        breakdown = {'critical': 0, 'high': 0,
                     'medium': 0, 'low': 0, 'info': 0}
        for v in self.vulnerabilities:
            breakdown[v.severity] = breakdown.get(v.severity, 0) + 1
        return breakdown


class Vulnerability(db.Model):
    id = db.Column(db.String(36), primary_key=True,
                   default=lambda: str(uuid.uuid4()))
    scan_id = db.Column(db.String(36), db.ForeignKey(
        'scan.id'), nullable=False)
    vuln_type = db.Column(db.String(100), nullable=False)
    # critical, high, medium, low, info
    severity = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    affected_url = db.Column(db.String(500))
    parameter = db.Column(db.String(100))
    payload = db.Column(db.Text)
    evidence = db.Column(db.Text)
    remediation = db.Column(db.Text)
    cvss_score = db.Column(db.Float, default=0.0)
    cwe_id = db.Column(db.String(20))
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    # ZAP plugin ID stored for deduplication when importing alerts multiple times
    zap_alert_id = db.Column(db.String(50))

    def to_dict(self):
        return {
            'id': self.id, 'scan_id': self.scan_id, 'vuln_type': self.vuln_type,
            'text': self.title,  # backup search text
            'severity': self.severity, 'title': self.title, 'description': self.description,
            'affected_url': self.affected_url, 'parameter': self.parameter,
            'payload': self.payload, 'evidence': self.evidence, 'remediation': self.remediation,
            'cvss_score': self.cvss_score, 'cwe_id': self.cwe_id,
            'zap_alert_id': self.zap_alert_id,
            'discovered_at': self.discovered_at.isoformat(),
            # Frontend compatibility mapping
            'scanId': self.scan_id,
            'ts': int(self.discovered_at.timestamp() * 1000) if self.discovered_at else int(datetime.utcnow().timestamp() * 1000)
        }


# ============ ADMIN DECORATOR ============
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user or user.role != 'admin':
            return jsonify({'error': 'Admin privilege required'}), 403
        return fn(*args, **kwargs)
    return wrapper


# ============ VULNERABILITY SCANNER ENGINE ============


# Thread-safe set of scan IDs that have been requested to cancel.
# The scanner thread checks this on each URL iteration and exits cleanly.
_cancelled_scans: set = set()
_cancel_lock = threading.Lock()


class VulnerabilityScanner:
    """Core scanning engine implementing OWASP Top 10 checks"""

    SQL_PAYLOADS = ["'", "''", "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--",
                    "1' AND '1'='1", "' UNION SELECT NULL--", "admin'--"]

    XSS_PAYLOADS = ['<script>alert("XSS")</script>', '"><script>alert(1)</script>',
                    "javascript:alert(1)", '<img src=x onerror=alert(1)>',
                    '<svg onload=alert(1)>', "';alert(String.fromCharCode(88,83,83))//"]

    # Parameters that commonly carry a URL/host the server will fetch. A match here
    # makes a parameter an SSRF *candidate* only — a finding still requires evidence.
    SSRF_PARAM_NAMES = {
        'url', 'uri', 'path', 'src', 'callback', 'webhook', 'image', 'proxy',
        'dest', 'destination', 'redirect', 'redirect_uri', 'target', 'fetch',
        'feed', 'host', 'domain', 'link', 'next', 'continue', 'site', 'load',
        'resource', 'file', 'to', 'out', 'view', 'page', 'u',
    }
    # Highly specific AWS instance-metadata tokens (IMDSv1 directory listing). We
    # require >= 2 DISTINCT matches so a page that merely contains one common word
    # can't be mistaken for reflected metadata.
    _SSRF_METADATA_RE = re.compile(
        r'(?i)\b(ami-id|ami-launch-index|instance-id|instance-type|local-ipv4|'
        r'public-ipv4|local-hostname|public-hostname|security-credentials|'
        r'reservation-id|public-keys|placement)\b')
    # a black-hole probe must hang at least this long (s)
    _SSRF_TIMING_MIN = 4.0
    # ... AND exceed the fast control by at least this (s)
    _SSRF_TIMING_DELTA = 3.0

    # A path segment that is a canonical UUID — treated as an object id for IDOR.
    _UUID_RE = re.compile(
        r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
        r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')

    def __init__(self, scan_id, target_url, config=None, socketio_instance=None):
        self.scan_id = scan_id
        self.target_url = target_url
        self.config = config or {}
        self.socketio = socketio_instance
        self.vulnerabilities = []
        self.visited_urls = set()
        self.urls_to_scan = [target_url]
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.get('user_agent', 'VulnScanner/1.0 (Security Research)'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        # Wire auth config (Cookie/Bearer token injection) for the primary identity.
        self._apply_auth(self.session, self.config.get('auth', {}))
        # Optional SECOND identity for active IDOR testing (config['auth_secondary'],
        # same {mode, value} shape). Built lazily on first use; see check_idor.
        self._secondary_session = 'unset'
        self.timeout = self.config.get('timeout', 10)
        self.max_depth = self.config.get('scan_depth', 3)
        self.found_forms = []

    def emit_progress(self, message, progress, url=None, vuln=None):
        """Emit real-time scan progress via WebSocket"""
        data = {'scan_id': self.scan_id,
                'message': message, 'progress': progress}
        if url:
            data['current_url'] = url
        if vuln:
            data['vulnerability'] = vuln
        if self.socketio:
            self.socketio.emit('scan_progress', data, room=self.scan_id)

    def crawl(self, url, depth=0):
        """Crawl website to discover URLs and forms"""
        if depth > self.max_depth or url in self.visited_urls:
            return
        self.visited_urls.add(url)
        try:
            response = self.session.get(
                url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            # Extract forms
            for form in soup.find_all('form'):
                form_data = {'url': url, 'method': form.get('method', 'get').lower(),
                             'action': form.get('action', ''), 'inputs': []}
                for inp in form.find_all(['input', 'textarea', 'select']):
                    form_data['inputs'].append({
                        'name': inp.get('name', ''), 'type': inp.get('type', 'text'),
                        'value': inp.get('value', '')
                    })
                self.found_forms.append(form_data)
            # Extract links
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('/'):
                    full_url = self.target_url.rstrip('/') + href
                elif href.startswith('http'):
                    if self.target_url in href:
                        full_url = href
                    else:
                        continue
                else:
                    continue
                if full_url not in self.visited_urls:
                    self.urls_to_scan.append(full_url)
        except Exception as e:
            logger.warning(f"Crawl error for {url}: {e}")

    def check_sql_injection(self, url, form=None):
        """Test for SQL injection vulnerabilities"""
        findings = []
        error_patterns = [
            r"SQL syntax.*MySQL", r"Warning.*mysql_fetch", r"MySQLSyntaxErrorException",
            r"ORA-\d{5}:", r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark after the character string",
            r"quoted string not properly terminated",
            r"SQLSTATE\[\w+\]", r"pg_query\(\): Query failed",
            r"supplied argument is not a valid MySQL result",
            r"You have an error in your SQL syntax",
            r"Warning: SQLite3::", r"SQLite/JDBCDriver",
        ]
        params_to_test = []
        if '?' in url:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params_to_test = list(params.keys())

        for payload in self.SQL_PAYLOADS[:3]:  # Test first 3 payloads
            try:
                if params_to_test:
                    test_url = url.split(
                        '?')[0] + '?' + '&'.join([f"{p}={payload}" for p in params_to_test])
                    response = self.session.get(
                        test_url, timeout=self.timeout, verify=False)
                    for pattern in error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            findings.append({
                                'vuln_type': 'sql_injection', 'severity': 'critical',
                                'title': 'SQL Injection Vulnerability Detected',
                                'description': 'The application appears to be vulnerable to SQL injection. User-supplied data is not properly sanitized before being included in SQL queries.',
                                'affected_url': url, 'parameter': params_to_test[0] if params_to_test else 'unknown',
                                'payload': payload,
                                'evidence': f'SQL error pattern detected: {pattern}',
                                'remediation': 'Use parameterized queries or prepared statements. Implement input validation and sanitization. Use an ORM framework.',
                                'cvss_score': 9.8, 'cwe_id': 'CWE-89'
                            })
                            return findings  # One finding per URL is enough
            except Exception:
                pass
        return findings

    def check_xss(self, url, form=None):
        """Test for reflected XSS — verify payload is unencoded in response"""
        findings = []
        if '?' not in url:
            return findings
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return findings

        for param_name in list(params.keys())[:5]:  # test up to 5 params
            for payload in self.XSS_PAYLOADS[:4]:
                try:
                    test_params = dict(params)
                    test_params[param_name] = [payload]
                    test_url = parsed.scheme + '://' + parsed.netloc + \
                        parsed.path + '?' + urlencode(test_params, doseq=True)
                    response = self.session.get(
                        test_url, timeout=self.timeout, verify=False)

                    body = response.text
                    ct = response.headers.get('Content-Type', '')

                    # Skip non-HTML responses (JSON APIs won't execute XSS)
                    if 'application/json' in ct or 'text/plain' in ct:
                        continue

                    # Require the raw (unencoded) payload to appear — not HTML-entity-encoded
                    # e.g. &lt;script&gt; is NOT a vulnerability
                    if payload not in body:
                        continue

                    # Extra: make sure it's not inside a benign attribute value already escaped
                    # Look for the script tag or event handler literally present
                    if '<script' in payload.lower() and '<script' not in body.lower():
                        continue

                    findings.append({
                        'vuln_type': 'xss', 'severity': 'high',
                        'title': f'Reflected XSS in parameter "{param_name}"',
                        'description': f'The parameter "{param_name}" reflects user input unencoded into the HTML response. An attacker can inject script that executes in victims\' browsers.',
                        'affected_url': url, 'parameter': param_name,
                        'payload': payload,
                        'evidence': f'Payload reflected verbatim in response (Content-Type: {ct.split(";")[0]}): {payload[:80]}',
                        'remediation': 'HTML-encode all output using context-appropriate escaping. Set a strict Content-Security-Policy. Never reflect unsanitised user input.',
                        'cvss_score': 7.4, 'cwe_id': 'CWE-79'
                    })
                    return findings  # one finding per URL is enough
                except Exception:
                    pass
        return findings

    def check_security_headers(self, url):
        """Check for missing security headers"""
        findings = []
        security_headers = {
            'X-Frame-Options': ('Clickjacking Protection Missing', 'medium', 'Add X-Frame-Options: DENY or SAMEORIGIN header', 5.4, 'CWE-1021'),
            'X-Content-Type-Options': ('MIME Sniffing Attack', 'low', 'Add X-Content-Type-Options: nosniff header', 4.3, 'CWE-16'),
            'Strict-Transport-Security': ('HSTS Not Implemented', 'medium', 'Implement HSTS with max-age of at least 31536000', 6.5, 'CWE-319'),
            'Content-Security-Policy': ('Content Security Policy Missing', 'medium', 'Implement a strict Content Security Policy', 6.1, 'CWE-16'),
            'X-XSS-Protection': ('XSS Filter Disabled', 'low', 'Enable XSS filter via X-XSS-Protection: 1; mode=block', 4.0, 'CWE-79'),
        }
        try:
            response = self.session.get(
                url, timeout=self.timeout, verify=False)
            for header, (title, severity, remediation, cvss, cwe) in security_headers.items():
                if header.lower() not in {k.lower() for k in response.headers.keys()}:
                    findings.append({
                        'vuln_type': 'security_misconfiguration', 'severity': severity,
                        'title': f'Missing Security Header: {header}',
                        'description': f'The HTTP response is missing the {header} security header, which can expose the application to {title}.',
                        'affected_url': url, 'parameter': 'HTTP Header',
                        'payload': None, 'evidence': f'Header {header} not found in response',
                        'remediation': remediation, 'cvss_score': cvss, 'cwe_id': cwe
                    })
        except Exception:
            pass
        return findings

    def check_ssl_tls(self, url):
        """Check SSL/TLS configuration"""
        findings = []
        if not url.startswith('https://'):
            findings.append({
                'vuln_type': 'sensitive_data_exposure', 'severity': 'high',
                'title': 'Insecure HTTP Protocol in Use',
                'description': 'The application is accessible over unencrypted HTTP, exposing all data in transit to interception.',
                'affected_url': url, 'parameter': 'Protocol',
                'payload': None, 'evidence': 'Application uses HTTP instead of HTTPS',
                'remediation': 'Enforce HTTPS for all connections. Obtain an SSL/TLS certificate and redirect all HTTP traffic to HTTPS.',
                'cvss_score': 7.5, 'cwe_id': 'CWE-319'
            })
        return findings

    def check_csrf(self, form_url, form_data):
        """Check for CSRF vulnerabilities in forms"""
        findings = []
        if form_data.get('method') == 'post':
            has_csrf_token = any(
                'csrf' in inp.get('name', '').lower(
                ) or 'token' in inp.get('name', '').lower()
                for inp in form_data.get('inputs', [])
            )
            if not has_csrf_token:
                findings.append({
                    'vuln_type': 'csrf', 'severity': 'medium',
                    'title': 'Cross-Site Request Forgery (CSRF) Token Missing',
                    'description': 'A POST form was found without CSRF protection tokens, making it vulnerable to CSRF attacks.',
                    'affected_url': form_url, 'parameter': 'Form',
                    'payload': None, 'evidence': f'POST form at {form_url} lacks CSRF token',
                    'remediation': 'Implement anti-CSRF tokens in all state-changing forms. Validate the Origin and Referer headers server-side.',
                    'cvss_score': 6.5, 'cwe_id': 'CWE-352'
                })
        return findings

    def check_open_redirect(self, url):
        """Check for open redirect vulnerabilities — actually probe, don't just flag by name"""
        findings = []
        redirect_params = ['redirect', 'url', 'next', 'return',
                           'goto', 'dest', 'destination', 'redir', 'target', 'link']
        CANARY = 'https://open-redirect-canary.example.com'
        if '?' in url:
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params.keys():
                if param.lower() in redirect_params:
                    # Build test URL with canary redirect value
                    test_params = dict(params)
                    test_params[param] = [CANARY]
                    test_url = urlunparse(parsed._replace(
                        query=urlencode(test_params, doseq=True)))
                    try:
                        resp = self.session.get(
                            test_url, timeout=self.timeout, verify=False, allow_redirects=False)
                        location = resp.headers.get('Location', '')
                        # Only flag if the server actually redirects to our canary value
                        if resp.status_code in (301, 302, 303, 307, 308) and CANARY in location:
                            findings.append({
                                'vuln_type': 'broken_access_control', 'severity': 'medium',
                                'title': 'Confirmed Open Redirect Vulnerability',
                                'description': f'The parameter "{param}" directly reflects the supplied URL in a redirect response, allowing attackers to redirect victims to malicious sites.',
                                'affected_url': url, 'parameter': param,
                                'payload': CANARY,
                                'evidence': f'Server returned {resp.status_code} Location: {location[:120]}',
                                'remediation': 'Validate redirect URLs against a whitelist of allowed destinations. Never redirect to an arbitrary user-supplied URL.',
                                'cvss_score': 5.4, 'cwe_id': 'CWE-601'
                            })
                    except Exception:
                        pass
        return findings

    def check_ssrf(self, url):
        """Detect Server-Side Request Forgery on URL-like parameters.

        Same false-positive discipline as check_open_redirect: a URL-ish parameter
        is only a *candidate*, never a finding on its own. We report ONLY on
        confirmed evidence, one of:
          (a) reflection — the response echoes content fetched from an internal
              target (>= 2 distinct cloud-metadata markers when the parameter is
              aimed at 169.254.169.254),
          (b) redirect — a 3xx Location header that points at the internal target, or
          (c) timing — aiming the parameter at a black-hole address (RFC5737
              TEST-NET, random high port) that forces a *server-side* connect
              timeout is markedly slower, and reproducibly so, than a control
              request to a fast-failing invalid host. That gap only appears if the
              server actually dials the address we supply, i.e. it is SSRF-able.

        Per the threat model we send probes aimed at 169.254.169.254, localhost and
        127.0.0.1:<random-high-port>. Note: a closed loopback port refuses instantly,
        so it is a poor *slow-timing* signal — the timing decision therefore uses an
        unrouted TEST-NET address to force the hang, while the loopback/metadata
        targets are exercised by the reflection and redirect probes above.
        """
        findings = []
        if '?' not in url:
            return findings
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return findings

        def _is_urlish(v):
            v = (v or '').strip().lower()
            return (v.startswith(('http://', 'https://', '//')) or
                    bool(re.match(r'^[a-z0-9.-]+:\d{1,5}(/|$)', v)))

        candidates = [name for name, vals in params.items()
                      if name.lower() in self.SSRF_PARAM_NAMES
                      or _is_urlish(vals[0] if vals else '')]
        if not candidates:
            return findings

        probe_timeout = min(self.timeout, 6)

        def _probe(param, value, allow_redirects=False):
            test_params = dict(params)
            test_params[param] = [value]
            test_url = urlunparse(parsed._replace(
                query=urlencode(test_params, doseq=True)))
            return self.session.get(test_url, timeout=probe_timeout,
                                    verify=False, allow_redirects=allow_redirects)

        def _timed(param, value):
            """Elapsed seconds for a probe; probe_timeout on timeout; None on other error."""
            t0 = time.monotonic()
            try:
                _probe(param, value)
                return time.monotonic() - t0
            except requests.exceptions.Timeout:
                return probe_timeout
            except Exception:
                return None

        INTERNAL_MARKERS = ('169.254.169.254', 'localhost', '127.0.0.1')

        for param in candidates[:2]:   # bound the probing cost per URL
            try:
                # (a) Reflection: aim at the cloud-metadata service; require >= 2
                #     distinct metadata markers echoed back in a 200 body.
                try:
                    r = _probe(
                        param, 'http://169.254.169.254/latest/meta-data/')
                    if r is not None and r.status_code == 200:
                        markers = {m.lower() for m in
                                   self._SSRF_METADATA_RE.findall(r.text or '')}
                        if len(markers) >= 2:
                            findings.append({
                                'vuln_type': 'ssrf', 'severity': 'critical',
                                'title': f'Server-Side Request Forgery (SSRF) in parameter "{param}"',
                                'description': f'The parameter "{param}" causes the server to fetch an attacker-supplied URL. Aimed at the cloud metadata endpoint (169.254.169.254) it returned instance metadata, which can expose IAM credentials and other secrets.',
                                'affected_url': url, 'parameter': param,
                                'payload': 'http://169.254.169.254/latest/meta-data/',
                                'evidence': f'Response reflected cloud-metadata fetched from 169.254.169.254 (markers: {", ".join(sorted(markers))})',
                                'remediation': 'Validate and allowlist outbound destinations; block link-local (169.254.0.0/16), loopback and private ranges; disable unneeded URL schemes; require IMDSv2.',
                                'cvss_score': 9.1, 'cwe_id': 'CWE-918'
                            })
                            return findings
                except Exception:
                    pass

                # (b) Redirect: a 3xx whose Location points at an internal address.
                port = random.randint(20000, 65500)
                for target in ('http://169.254.169.254/', 'http://localhost/',
                               f'http://127.0.0.1:{port}/'):
                    try:
                        r = _probe(param, target, allow_redirects=False)
                        loc = r.headers.get(
                            'Location', '') if r is not None else ''
                        if (r is not None and r.status_code in (301, 302, 303, 307, 308)
                                and any(h in loc for h in INTERNAL_MARKERS)):
                            findings.append({
                                'vuln_type': 'ssrf', 'severity': 'high',
                                'title': f'Server-Side Request Forgery (SSRF) in parameter "{param}"',
                                'description': f'The parameter "{param}" is reflected into a redirect pointing at an internal address, letting an attacker make the server issue requests to internal-only services.',
                                'affected_url': url, 'parameter': param,
                                'payload': target,
                                'evidence': f'Server returned {r.status_code} Location: {loc[:120]}',
                                'remediation': 'Validate and allowlist outbound destinations; block link-local, loopback and private ranges; never place unvalidated input in a redirect target.',
                                'cvss_score': 7.5, 'cwe_id': 'CWE-918'
                            })
                            return findings
                    except Exception:
                        pass

                # (c) Timing: black-hole (server-side connect hangs) vs invalid-host
                #     control (fast DNS failure). A large, reproducible gap only
                #     occurs if the server actually dials the supplied address.
                bh_port = random.randint(20000, 65500)
                # RFC5737, unrouted
                blackhole = f'http://192.0.2.1:{bh_port}/'
                # NXDOMAIN
                control = f'http://ssrf-control-{secrets.token_hex(4)}.invalid/'
                t_control = _timed(param, control)
                t_black = _timed(param, blackhole)
                if (t_control is not None and t_black is not None
                        and t_black >= self._SSRF_TIMING_MIN
                        and (t_black - t_control) >= self._SSRF_TIMING_DELTA):
                    # reproduce to reject jitter
                    t_black2 = _timed(param, blackhole)
                    if t_black2 is not None and t_black2 >= self._SSRF_TIMING_MIN:
                        findings.append({
                            'vuln_type': 'ssrf', 'severity': 'high',
                            'title': f'Server-Side Request Forgery (SSRF) in parameter "{param}"',
                            'description': f'The parameter "{param}" appears to trigger a server-side request to the supplied address. An unrouted internal black-hole forced a connect timeout on the server while a fast-failing control did not — a timing signature consistent with blind SSRF.',
                            'affected_url': url, 'parameter': param,
                            'payload': blackhole,
                            'evidence': f'Timing signature: invalid-host control={t_control:.2f}s vs internal black-hole={t_black:.2f}s (repeat {t_black2:.2f}s)',
                            'remediation': 'Validate and allowlist outbound destinations; block link-local, loopback and private ranges; enforce short egress timeouts and disable unneeded URL schemes.',
                            'cvss_score': 7.2, 'cwe_id': 'CWE-918'
                        })
                        return findings
            except Exception:
                pass
        return findings

    def _apply_auth(self, session, auth):
        """Inject Cookie/Bearer auth from an {mode, value} config onto a session."""
        if not isinstance(auth, dict):
            return
        mode = auth.get('mode', 'none')
        val = (auth.get('value') or '').strip()
        if mode == 'cookie' and val:
            session.headers.update({'Cookie': val})
        elif mode == 'bearer' and val:
            session.headers.update({'Authorization': f"Bearer {val}"})

    def _get_secondary_session(self):
        """Lazily build the second-identity session from config['auth_secondary'].
        Returns None when no secondary credential is configured (IDOR then skips)."""
        if self._secondary_session != 'unset':
            return self._secondary_session
        auth = self.config.get('auth_secondary')
        if not isinstance(auth, dict):
            auth = {}
        if not (auth.get('value') or '').strip():
            self._secondary_session = None
            return None
        s = requests.Session()
        s.headers.update({
            'User-Agent': self.config.get('user_agent', 'VulnScanner/1.0 (Security Research)'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        self._apply_auth(s, auth)
        self._secondary_session = s
        return s

    def check_idor(self, url):
        """Active IDOR test using a SECOND authenticated identity.

        Requires config['auth_secondary'] (same {mode, value} shape as
        config['auth']). If it is absent, the check skips gracefully (returns [])
        rather than erroring. For a URL whose path carries a numeric or UUID object
        id (e.g. /api/projects/42, /api/users/<uuid>) we:
          1. confirm identity A (the primary scan session) can read it (HTTP 200);
          2. request the SAME resource as identity B (auth_secondary);
          3. establish B's "access denied" baseline by requesting a random NON-owned
             id of the same type as B — a properly-scoped endpoint answers 401/403/404.

        We flag IDOR only when B is denied the non-owned probe (so object-level
        authorization demonstrably exists) YET is still served A's object with a 200
        whose body differs from that denial — i.e. B can read a resource it does not
        own. Never flags on assumption: a public endpoint (probe also 200) or a
        properly-scoped one (B denied the target) yields nothing.
        """
        findings = []
        sec = self._get_secondary_session()
        if sec is None:
            return findings   # no secondary credential -> skip gracefully

        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        segments = parsed.path.split('/')
        idx, id_type = None, None
        for i in range(len(segments) - 1, -1, -1):     # trailing id is the usual case
            seg = segments[i]
            if seg.isdigit():
                idx, id_type = i, 'numeric'
                break
            if self._UUID_RE.match(seg):
                idx, id_type = i, 'uuid'
                break
        if idx is None:
            return findings   # no object id in the path

        orig_id = segments[idx]

        def _fetch(session, u):
            try:
                r = session.get(u, timeout=self.timeout, verify=False,
                                allow_redirects=False)
                return r.status_code, (r.text or '')
            except Exception:
                return None, ''

        # 1) Identity A must actually be able to read the resource.
        a_status, a_body = _fetch(self.session, url)
        if a_status != 200:
            return findings

        # 2) Identity B requests the SAME resource.
        b_status, b_body = _fetch(sec, url)
        if b_status != 200:
            return findings   # B is properly denied -> no IDOR

        # 3) B's "denied" baseline: a random non-owned id of the same type.
        if id_type == 'numeric':
            probe_id = str(random.randint(10**8, 10**9))
            if probe_id == orig_id:
                probe_id = str(int(probe_id) + 7)
        else:
            probe_id = str(uuid.uuid4())
        probe_segments = list(segments)
        probe_segments[idx] = probe_id
        probe_url = urlunparse(parsed._replace(path='/'.join(probe_segments)))
        p_status, p_body = _fetch(sec, probe_url)

        # Flag only if the endpoint DENIES a non-owned id (baseline enforced) but
        # still served A's object to B with different content.
        if p_status in (401, 403, 404) and b_body.strip() != p_body.strip():
            same = (" B's response body matches identity A's view of the object."
                    if b_body.strip() == a_body.strip() else '')
            findings.append({
                'vuln_type': 'idor', 'severity': 'high',
                'title': f'Insecure Direct Object Reference (IDOR) at {parsed.path}',
                'description': (
                    f'A second authenticated identity (B) read object "{orig_id}", which it '
                    f'does not own. The endpoint denies a random non-owned id ({p_status}) but '
                    f'serves this object to B with 200, so object-level authorization is '
                    f'missing.' + same),
                'affected_url': url, 'parameter': f'object id ({id_type})',
                'payload': f'{orig_id} requested with secondary credentials',
                'evidence': (f'A(owner)={a_status}, B(target id {orig_id})={b_status}, '
                             f'B(non-owned probe {probe_id})={p_status}'),
                'remediation': 'Enforce object-level authorization on every request: verify the authenticated principal owns or is permitted the requested id before returning it. Prefer unpredictable identifiers as defense in depth.',
                'cvss_score': 8.1, 'cwe_id': 'CWE-639'
            })
        return findings

    def check_information_disclosure(self, url):
        """Check for sensitive information disclosure with severity calibrated per path"""
        findings = []
        # (path, severity, cvss, confirm_content_pattern)
        # confirm_content_pattern: regex that must match response body to avoid false positives
        sensitive_paths = [
            ('/.git/HEAD',      'high',   8.1, r'ref: refs/'),
            ('/.env',           'high',   8.1,
             r'(?i)(DB_|APP_KEY|SECRET|PASSWORD|TOKEN)'),
            ('/phpinfo.php',    'medium', 6.5, r'(?i)PHP Version'),
            ('/server-status',  'medium', 5.3,
             r'(?i)(Apache|Server uptime|requests currently being)'),
            ('/web.config',     'high',   8.1, r'(?i)<configuration>'),
            # directory listing — checked by content
            ('/backup',         'medium', 5.3, None),
            # just note it exists; not always a vuln
            ('/admin',          'info',   3.1, None),
            ('/config',         'info',   3.1, None),
            ('/api/swagger.json', 'medium', 5.3, r'(?i)"swagger"'),
            ('/api/openapi.json', 'medium', 5.3, r'(?i)"openapi"'),
        ]
        for path, severity, cvss, pattern in sensitive_paths:
            test_url = self.target_url.rstrip('/') + path
            try:
                response = self.session.get(test_url, timeout=5, verify=False)
                if response.status_code != 200:
                    continue
                body = response.text
                # For paths with a content confirmation pattern, require it to match
                if pattern and not re.search(pattern, body):
                    continue
                # For directory-listing paths, require Index Of pattern
                if path in ('/backup', '/admin', '/config') and not re.search(r'(?i)Index of /', body):
                    severity = 'info'  # downgrade — may just be a login page
                findings.append({
                    'vuln_type': 'sensitive_data_exposure', 'severity': severity,
                    'title': f'Sensitive Resource Accessible: {path}',
                    'description': f'The path {path} returned HTTP 200 with content matching a sensitive pattern. This may expose credentials, configuration, or server internals.',
                    'affected_url': test_url, 'parameter': 'URL Path',
                    'payload': None,
                    'evidence': f'HTTP 200 — body matched pattern: {pattern or "directory listing"}',
                    'remediation': 'Block access to sensitive paths at the web server or firewall level. Remove debug/backup files from the web root.',
                    'cvss_score': cvss, 'cwe_id': 'CWE-200'
                })
            except Exception:
                pass
        return findings

    def check_cors(self, url):
        """Check for overly permissive CORS configuration"""
        findings = []
        try:
            resp = self.session.options(url, timeout=self.timeout, verify=False,
                                        headers={'Origin': 'https://evil.example.com'})
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get(
                'Access-Control-Allow-Credentials', '').lower()
            if acao == '*':
                findings.append({
                    'vuln_type': 'security_misconfiguration', 'severity': 'medium',
                    'title': 'Wildcard CORS Policy (Access-Control-Allow-Origin: *)',
                    'description': 'The server allows any origin to make cross-origin requests. Combined with credentials this can lead to data theft.',
                    'affected_url': url, 'parameter': 'CORS Header',
                    'payload': None, 'evidence': 'Access-Control-Allow-Origin: *',
                    'remediation': 'Restrict CORS to trusted origins. Never combine wildcard with credentials.',
                    'cvss_score': 5.3, 'cwe_id': 'CWE-942'
                })
            elif acao == 'https://evil.example.com':
                sev = 'high' if acac == 'true' else 'medium'
                cvss = 8.1 if acac == 'true' else 5.3
                findings.append({
                    'vuln_type': 'security_misconfiguration', 'severity': sev,
                    'title': 'CORS Origin Reflection' + (' with Credentials' if acac == 'true' else ''),
                    'description': 'The server reflects arbitrary Origin values back, allowing cross-origin requests from any domain' + ('. With credentials allowed, authenticated data can be exfiltrated.' if acac == 'true' else '.'),
                    'affected_url': url, 'parameter': 'CORS Header',
                    'payload': 'Origin: https://evil.example.com',
                    'evidence': f'Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}',
                    'remediation': 'Maintain an explicit allowlist of trusted origins. Never reflect arbitrary Origin values. Never set credentials=true with a dynamic origin.',
                    'cvss_score': cvss, 'cwe_id': 'CWE-942'
                })
        except Exception:
            pass
        return findings

    def check_clickjacking(self, url):
        """Verify clickjacking protection (X-Frame-Options or CSP frame-ancestors)"""
        findings = []
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            xfo = resp.headers.get('X-Frame-Options', '')
            csp = resp.headers.get('Content-Security-Policy', '')
            has_frame_ancestors = 'frame-ancestors' in csp.lower()
            if not xfo and not has_frame_ancestors:
                findings.append({
                    'vuln_type': 'security_misconfiguration', 'severity': 'medium',
                    'title': 'Clickjacking — Missing Frame Protection',
                    'description': 'Neither X-Frame-Options nor CSP frame-ancestors is set. The page can be embedded in an attacker-controlled iframe to trick users into clicking hidden UI elements.',
                    'affected_url': url, 'parameter': 'HTTP Header',
                    'payload': None, 'evidence': 'X-Frame-Options absent, CSP frame-ancestors absent',
                    'remediation': "Add 'Content-Security-Policy: frame-ancestors \'self\'' or 'X-Frame-Options: SAMEORIGIN'.",
                    'cvss_score': 4.7, 'cwe_id': 'CWE-1021'
                })
        except Exception:
            pass
        return findings

    def run_scan(self):
        """Main scan execution — runs in background thread with explicit app context"""
        from flask import current_app
        with app.app_context():
            self._run_scan_inner()

    def _run_scan_inner(self):
        scan = Scan.query.get(self.scan_id)
        if not scan:
            return
        scan.status = 'running'
        scan.started_at = datetime.utcnow()
        db.session.commit()
        self.emit_progress('Scan started - Initializing crawler...', 5)

        # Phase 1: Crawl
        self.emit_progress(
            'Phase 1: Crawling target website...', 10, self.target_url)
        self.crawl(self.target_url)
        # Cap at 20 for performance
        total_urls = min(len(self.urls_to_scan), 20)
        scan.total_urls = total_urls
        db.session.commit()

        # Phase 2: Active scanning
        self.emit_progress('Phase 2: Running vulnerability checks...', 20)
        all_vulns = []
        all_vulns.extend(self.check_ssl_tls(self.target_url))
        all_vulns.extend(self.check_security_headers(self.target_url))
        all_vulns.extend(self.check_information_disclosure(self.target_url))
        all_vulns.extend(self.check_cors(self.target_url))
        all_vulns.extend(self.check_clickjacking(self.target_url))

        for i, url in enumerate(list(self.urls_to_scan)[:total_urls]):
            # Check for cancellation before each URL
            with _cancel_lock:
                if self.scan_id in _cancelled_scans:
                    scan.status = 'cancelled'
                    scan.completed_at = datetime.utcnow()
                    db.session.commit()
                    self.emit_progress(
                        'Scan cancelled by user.', scan.progress)
                    with _cancel_lock:
                        _cancelled_scans.discard(self.scan_id)
                    return []
            progress = 20 + int((i / total_urls) * 60)
            self.emit_progress(f'Scanning: {url[:60]}...', progress, url)
            all_vulns.extend(self.check_sql_injection(url))
            all_vulns.extend(self.check_xss(url))
            all_vulns.extend(self.check_open_redirect(url))
            all_vulns.extend(self.check_ssrf(url))
            all_vulns.extend(self.check_idor(url))
            scan.scanned_urls = i + 1
            db.session.commit()
            time.sleep(0.5)  # Throttle requests

        # Phase 3: Form testing
        self.emit_progress('Phase 3: Testing forms for CSRF...', 85)
        for form in self.found_forms:
            all_vulns.extend(self.check_csrf(form['url'], form))

        # Save vulnerabilities to DB
        self.emit_progress('Phase 4: Saving results...', 95)
        for vuln_data in all_vulns:
            vuln = Vulnerability(scan_id=self.scan_id, **vuln_data)
            db.session.add(vuln)
            try:
                db.session.add(AuditLog(
                    event_type='vuln_found',
                    username='system',
                    ip_address='127.0.0.1',
                    details=f"Vulnerability discovered: [{vuln.severity.upper()}] {vuln.title} (Scan ID: {self.scan_id})"
                ))
            except Exception:
                pass

        scan.status = 'completed'
        scan.progress = 100
        scan.completed_at = datetime.utcnow()
        db.session.commit()
        self.emit_progress('Scan completed successfully!', 100)
        return all_vulns

# ============ SCAN DISPATCH (Celery task or threading fallback) ============
# One entry point, two backends. dispatch_scan() is what the API and scheduler
# call; it hides whether the scan runs in a Celery worker or a local thread.


if _CELERY_ENABLED:
    @celery_app.task(name='vulnscan.run_scan')
    def run_scan_task(scan_id, target_url, config):
        """Run a scan inside the Celery worker process.

        Progress is emitted through an EMIT-ONLY Socket.IO client bound to the same
        Redis message queue as the web server, so 'scan_progress' events published
        here are delivered to the browser clients connected to the web process.
        """
        worker_sio = SocketIO(message_queue=REDIS_URL)
        scanner = VulnerabilityScanner(scan_id, target_url, config, worker_sio)
        scanner.run_scan()   # wraps app.app_context() + _run_scan_inner()
else:
    run_scan_task = None


def dispatch_scan(scan_id, target_url, config):
    """Start a scan. Uses Celery when REDIS_URL is configured, otherwise falls back
    to a daemon thread so the app runs with zero extra infrastructure."""
    if _CELERY_ENABLED and run_scan_task is not None:
        run_scan_task.delay(scan_id, target_url, config)
        logger.info("scan %s enqueued to Celery worker", scan_id)
    else:
        scanner = VulnerabilityScanner(scan_id, target_url, config, socketio)
        thread = threading.Thread(target=scanner.run_scan)
        thread.daemon = True
        thread.start()
        logger.info(
            "scan %s started in background thread (threading fallback)", scan_id)


# ─── ZAP Scan State Tracking ─────────────────────────────────────────────────
# Maps VulnScanPro scan_id → {'spider_id': str|None, 'ascan_id': str|None}
# Used by /api/zap/scan/stop to send stop signals to ZAP.
_zap_active_scans: dict = {}
_zap_scan_lock = threading.Lock()


class _ZapScanCancelled(Exception):
    """Raised inside run_zap_scan_bg to abort the scan cleanly."""


def run_zap_scan_bg(scan_id: str, target_url: str, config: dict) -> None:
    """
    Full ZAP scan orchestration — runs inside a background daemon thread.

    Workflow:
        1. Validate ZAP is reachable
        2. Create fresh ZAP session
        3. Spider → wait
        4. Passive scan → wait
        5. Active scan → wait
        6. Fetch and map alerts → save Vulnerability rows
        7. Mark Scan as completed / failed / cancelled

    Progress is broadcast to the browser via Socket.IO 'scan_progress' events
    using the same room/event contract as the native VulnerabilityScanner.
    ZAP_API_URL and ZAP_API_KEY are never logged or returned to the client.
    """
    logger.info('[ZAP] run_zap_scan_bg started — scan_id=%s target=%s', scan_id, target_url)

    def _emit(message: str, progress: int, vuln_data: dict = None):
        """Emit a scan_progress Socket.IO event AND persist progress to DB.

        Persisting to the DB on every step means the HTTP polling fallback
        always reads the correct live progress, even when Socket.IO events
        are dropped (e.g. WinError 10038 / browser not yet in room).
        """
        # ── Persist progress so HTTP polling sees real-time state ──────────
        try:
            if scan.progress != progress:
                scan.progress = progress
                db.session.commit()
        except Exception as _pe:
            logger.debug('[ZAP] progress DB persist failed: %s', _pe)
        # ── Emit over Socket.IO (best-effort) ─────────────────────────────
        payload = {'scan_id': scan_id, 'message': message, 'progress': progress}
        if vuln_data:
            payload['vulnerability'] = vuln_data
        try:
            socketio.emit('scan_progress', payload, room=scan_id)
        except Exception as _e:
            logger.warning('[ZAP] socketio.emit failed: %s', _e)

    def _is_cancelled() -> bool:
        """Return True if the scan has been requested to stop."""
        with _zap_scan_lock:
            entry = _zap_active_scans.get(scan_id, {})
            return entry.get('cancelled', False)

    with app.app_context():
        # ── 0. Load the scan record ────────────────────────────────────────
        scan = Scan.query.get(scan_id)
        if not scan:
            logger.error('[ZAP] Scan %s not found in DB — aborting', scan_id)
            return

        try:
            # Mark as running and set initial progress so polling sees it
            scan.status = 'running'
            scan.progress = 2
            scan.started_at = datetime.utcnow()
            db.session.commit()
            _emit('ZAP scan initialising…', 2)

            # ── 1. ZAP health check ────────────────────────────────────────
            _emit('Checking ZAP availability…', 5)
            availability = zap_service.check_zap_availability()
            if not availability.get('reachable'):
                msg = availability.get('message', 'ZAP is not reachable.')
                logger.error('[ZAP] Scan %s aborted — ZAP unreachable: %s', scan_id, msg)
                scan.status = 'failed'
                scan.completed_at = datetime.utcnow()
                db.session.commit()
                _emit(f'ZAP unavailable: {msg}', 0)
                return
            logger.info('[ZAP] ZAP version %s confirmed reachable', availability.get('version'))
            _emit(f'ZAP {availability.get("version", "")} is online', 8)

            if _is_cancelled():
                raise _ZapScanCancelled()

            # ── 2. New ZAP session ─────────────────────────────────────────
            _emit('Creating a fresh ZAP session…', 10)
            session_name = scan_id[:8]
            zap_service.new_session(session_name)
            zap_service.set_zap_mode('standard')

            # Register this scan in the active-scans tracker so /stop can reach it
            with _zap_scan_lock:
                _zap_active_scans[scan_id] = {
                    'spider_id': None,
                    'ascan_id': None,
                    'cancelled': False,
                }

            if _is_cancelled():
                raise _ZapScanCancelled()

            # ── 3. Spider scan ─────────────────────────────────────────────
            max_depth = config.get('scan_depth', 5)
            _emit('Starting spider crawl…', 12)
            spider_id = zap_service.start_spider(target_url, max_depth=max_depth)
            scan.zap_scan_id = spider_id
            scan.progress = 12
            db.session.commit()

            with _zap_scan_lock:
                if scan_id in _zap_active_scans:
                    _zap_active_scans[scan_id]['spider_id'] = spider_id

            def _spider_cb(pct: int, msg: str):
                # Map spider 0–100 to overall 12–40
                overall = 12 + int(pct * 0.28)
                scan.progress = overall
                db.session.commit()
                _emit(msg, overall)

            discovered_urls = zap_service.wait_for_spider(
                spider_id,
                progress_callback=_spider_cb,
                cancelled_check=_is_cancelled,
            )
            scan.total_urls = len(discovered_urls)
            db.session.commit()
            _emit(f'Spider complete — {len(discovered_urls)} URL(s) found', 40)
            logger.info('[ZAP] Spider done — %d URL(s)', len(discovered_urls))

            if _is_cancelled():
                raise _ZapScanCancelled()

            # ── 4. Passive scan ────────────────────────────────────────────
            _emit('Running passive scan analysis…', 42)

            def _pscan_cb(pct: int, msg: str):
                overall = 42 + int(pct * 0.08)  # 42–50 range while waiting
                scan.progress = overall
                db.session.commit()
                _emit(msg, overall)

            zap_service.wait_for_passive_scan(
                progress_callback=_pscan_cb,
                cancelled_check=_is_cancelled,
            )
            scan.progress = 50
            db.session.commit()
            _emit('Passive scan complete', 50)

            if _is_cancelled():
                raise _ZapScanCancelled()

            # ── 5. Active scan ─────────────────────────────────────────────
            _emit('Starting active (attack) scan…', 52)
            
            # Verify the target host is in ZAP's sites map before running active scan.
            # If ZAP failed to connect to the target during spider crawl (connection timeout/refused),
            # the domain won't be in the scan tree, and active scan will throw a cryptic 400 url_not_found.
            try:
                from urllib.parse import urlparse
                target_host = urlparse(target_url).netloc.lower().split(':')[0]
                sites_data = zap_service._zap_request('/JSON/core/view/sites/')
                sites = sites_data.get('sites', [])
                has_site = False
                for site in sites:
                    if urlparse(site).netloc.lower().split(':')[0] == target_host:
                        has_site = True
                        break
                if not has_site:
                    raise zap_service.ZapScanError(
                        f"ZAP could not connect to '{target_host}'. Connection timed out during spider crawl. "
                        "Verify the target URL is correct, online, and accepts incoming connections."
                    )
            except Exception as _e:
                if isinstance(_e, zap_service.ZapScanError):
                    raise _e
                logger.warning('[ZAP] Pre-scan sites check failed to run: %s', _e)

            scan_policy = config.get('scan_policy', '')
            ascan_id = zap_service.start_active_scan(target_url, scan_policy=scan_policy)
            scan.zap_scan_id = ascan_id
            db.session.commit()


            with _zap_scan_lock:
                if scan_id in _zap_active_scans:
                    _zap_active_scans[scan_id]['ascan_id'] = ascan_id

            def _ascan_cb(pct: int, msg: str):
                # Map active-scan 0–100 to overall 52–90
                overall = 52 + int(pct * 0.38)
                scan.progress = overall
                scan.scanned_urls = int(len(discovered_urls) * pct / 100)
                db.session.commit()
                _emit(msg, overall)

            zap_service.wait_for_active_scan(
                ascan_id,
                progress_callback=_ascan_cb,
                cancelled_check=_is_cancelled,
            )
            scan.progress = 90
            db.session.commit()
            _emit('Active scan complete — collecting results…', 90)

            if _is_cancelled():
                raise _ZapScanCancelled()

            # ── 6. Fetch alerts and persist vulnerabilities ────────────────
            _emit('Importing ZAP alerts…', 92)
            try:
                alerts = zap_service.get_alerts(base_url=target_url)
            except zap_service.ZapError as exc:
                logger.warning('[ZAP] Could not fetch alerts for %s: %s', scan_id, exc)
                alerts = []

            logger.info('[ZAP] %d alert(s) returned for scan %s', len(alerts), scan_id)

            # Deduplicate by zap_alert_id + affected_url to avoid double-importing
            existing_keys = set()
            for row in Vulnerability.query.filter_by(scan_id=scan_id).all():
                existing_keys.add((row.zap_alert_id, row.affected_url))

            imported = 0
            for alert in alerts:
                vuln_dict = zap_service.map_alert_to_vulnerability(alert, scan_id)
                key = (vuln_dict.get('zap_alert_id'), vuln_dict.get('affected_url'))
                if key in existing_keys:
                    continue
                existing_keys.add(key)

                # Strip the helper field before passing to the ORM constructor
                zap_alert_id = vuln_dict.pop('zap_alert_id', None)
                vuln = Vulnerability(zap_alert_id=zap_alert_id, **vuln_dict)
                db.session.add(vuln)

                try:
                    db.session.add(AuditLog(
                        event_type='vuln_found',
                        username='system',
                        ip_address='127.0.0.1',
                        details=(
                            f'[ZAP] [{vuln.severity.upper()}] {vuln.title} '
                            f'at {vuln.affected_url} (Scan: {scan_id})'
                        )
                    ))
                except Exception:
                    pass

                # Emit each new finding to the browser in real-time
                _emit(
                    f'Found: [{vuln.severity.upper()}] {vuln.title}',
                    92,
                    vuln_data={
                        'title': vuln.title,
                        'severity': vuln.severity,
                        'affected_url': vuln.affected_url,
                        'vuln_type': vuln.vuln_type,
                        'description': vuln.description,
                        'cvss_score': vuln.cvss_score,
                    }
                )
                imported += 1

            db.session.commit()
            logger.info('[ZAP] %d vulnerability/vulnerabilities saved for scan %s', imported, scan_id)

            # ── 7. Mark scan as completed ──────────────────────────────────
            scan.status = 'completed'
            scan.progress = 100
            scan.completed_at = datetime.utcnow()
            db.session.commit()
            _emit(f'Scan complete — {imported} finding(s) imported', 100)
            logger.info('[ZAP] Scan %s completed successfully', scan_id)

        except _ZapScanCancelled:
            logger.info('[ZAP] Scan %s was cancelled', scan_id)
            scan.status = 'cancelled'
            scan.completed_at = datetime.utcnow()
            db.session.commit()
            _emit('Scan cancelled by user.', scan.progress or 0)

        except zap_service.ZapTimeoutError as exc:
            logger.error('[ZAP] Scan %s timed out: %s', scan_id, exc)
            scan.status = 'failed'
            scan.completed_at = datetime.utcnow()
            db.session.commit()
            _emit(f'Scan timed out: {exc}', scan.progress or 0)

        except zap_service.ZapError as exc:
            logger.error('[ZAP] Scan %s ZAP error: %s', scan_id, exc)
            scan.status = 'failed'
            scan.completed_at = datetime.utcnow()
            db.session.commit()
            
            # Translate cryptic ZAP url_not_found or 400 responses into user-friendly message
            err_msg = str(exc)
            if 'url_not_found' in err_msg or 'URL Not Found' in err_msg:
                err_msg = "ZAP could not reach the target site (connection timed out). Verify that the URL is online and accessible."
            
            _emit(f'ZAP error: {err_msg}', scan.progress or 0)


        except Exception as exc:
            logger.exception('[ZAP] Scan %s unexpected error: %s', scan_id, exc)
            try:
                scan.status = 'failed'
                scan.completed_at = datetime.utcnow()
                db.session.commit()
            except Exception:
                db.session.rollback()
            _emit(f'Scan failed unexpectedly: {exc}', scan.progress or 0)

        finally:
            # Always clean up the active-scans registry
            with _zap_scan_lock:
                _zap_active_scans.pop(scan_id, None)



def dispatch_zap_scan(scan_id: str, target_url: str, config: dict) -> None:
    """
    Launch a ZAP scan as a Flask-SocketIO background task.
    """
    socketio.start_background_task(
        run_zap_scan_bg,
        scan_id,
        target_url,
        config
    )

    logger.info('[ZAP] ZAP scan %s dispatched to background task', scan_id)
# ============ REPORT GENERATOR ============


class ReportGenerator:
    """Generate comprehensive PDF vulnerability reports using ReportLab"""

    @staticmethod
    def generate_pdf(scan_id):
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        import io

        scan = Scan.query.get(scan_id)
        if not scan:
            return None

        target = scan.target
        vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()
        severity_colors = {
            'critical': colors.HexColor('#DC2626'),
            'high': colors.HexColor('#EA580C'),
            'medium': colors.HexColor('#D97706'),
            'low': colors.HexColor('#2563EB'),
            'info': colors.HexColor('#059669')
        }

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            'Title', parent=styles['Title'], fontSize=28, textColor=colors.HexColor('#0F172A'), spaceAfter=6)
        story.append(
            Paragraph("Web Application Vulnerability Assessment Report", title_style))
        story.append(Spacer(1, 12))

        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading1']))
        breakdown = scan._severity_breakdown()
        total = sum(breakdown.values())
        summary = f"Scan completed on {scan.completed_at.strftime('%Y-%m-%d %H:%M')} for target: {target.url}. Total {total} vulnerabilities found: {breakdown['critical']} Critical, {breakdown['high']} High, {breakdown['medium']} Medium, {breakdown['low']} Low, {breakdown['info']} Informational."
        story.append(Paragraph(summary, styles['Normal']))
        story.append(Spacer(1, 12))

        # Summary Table
        table_data = [['Severity', 'Count', 'Risk Level'],
                      ['Critical', str(breakdown['critical']),
                       'Immediate Action Required'],
                      ['High', str(breakdown['high']), 'Fix Within 24 Hours'],
                      ['Medium', str(breakdown['medium']),
                       'Fix Within 7 Days'],
                      ['Low', str(breakdown['low']), 'Fix Within 30 Days'],
                      ['Info', str(breakdown['info']), 'Informational']]

        table = Table(table_data, colWidths=[2*inch, 1.5*inch, 3*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.HexColor('#F8FAFC'), colors.white]),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
        ]))
        story.append(table)
        story.append(Spacer(1, 24))

        # Detailed Findings
        story.append(Paragraph("Detailed Findings", styles['Heading1']))
        for i, vuln in enumerate(vulns, 1):
            story.append(Paragraph(f"{i}. {vuln.title}", styles['Heading2']))
            data = [
                ['Severity', vuln.severity.upper()],
                ['Type', vuln.vuln_type.replace('_', ' ').title()],
                ['Affected URL', vuln.affected_url or 'N/A'],
                ['CVSS Score', str(vuln.cvss_score)],
                ['CWE', vuln.cwe_id or 'N/A'],
            ]
            t = Table(data, colWidths=[2*inch, 4*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F1F5F9')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ]))
            story.append(t)
            story.append(Spacer(1, 6))
            story.append(
                Paragraph(f"<b>Description:</b> {vuln.description}", styles['Normal']))
            if vuln.remediation:
                story.append(
                    Paragraph(f"<b>Remediation:</b> {vuln.remediation}", styles['Normal']))
            story.append(Spacer(1, 12))

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()

# ============ INPUT VALIDATION & SANITIZATION (Pydantic) ============
# Server-side validation for every auth form field. These checks run on EVERY
# request regardless of any client-side validation — the client is never trusted.


# Sanitization patterns (applied to rendered identity fields only)
_SCRIPT_BLOCK_RE = re.compile(
    r'<script\b[^>]*>.*?</script\s*>', re.IGNORECASE | re.DOTALL)
_HTML_TAG_RE = re.compile(r'<[^>]*>')
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x1f\x7f]')

# Field format rules
_USERNAME_RE = re.compile(r'^[A-Za-z0-9._-]{3,30}$')
_EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
_DISPLAY_NAME_RE = re.compile(r"^[A-Za-z0-9 .,'\-]{1,50}$")


def sanitize_text(value):
    """Strip script blocks, HTML tags, encoded markup, and control characters.

    Applied to *rendered* identity fields (username, email, display name) to defend
    against stored/reflected XSS. NOT applied to passwords: a password is hashed and
    never rendered, so stripping characters from it would silently weaken credentials.
    """
    if not isinstance(value, str):
        return value
    cleaned = _SCRIPT_BLOCK_RE.sub('', value)
    cleaned = _HTML_TAG_RE.sub('', cleaned)
    # Decode entities so encoded payloads (e.g. &lt;script&gt;) can't slip through,
    # then strip again in case decoding revealed a tag.
    cleaned = html.unescape(cleaned)
    cleaned = _SCRIPT_BLOCK_RE.sub('', cleaned)
    cleaned = _HTML_TAG_RE.sub('', cleaned)
    cleaned = _CONTROL_CHARS_RE.sub('', cleaned)
    return cleaned.strip()


class RegisterSchema(BaseModel):
    """Validation schema for POST /api/auth/register."""
    model_config = {
        # silently drop unexpected fields (e.g. confirm_password)
        'extra': 'ignore'}

    username: str
    email: str
    password: str
    display_name: str | None = None

    @field_validator('username')
    @classmethod
    def _validate_username(cls, v):
        v = sanitize_text(v)
        if not _USERNAME_RE.match(v):
            raise ValueError(
                'username must be 3-30 chars: letters, digits, . _ -')
        return v

    @field_validator('email')
    @classmethod
    def _validate_email(cls, v):
        v = sanitize_text(v).lower()
        if len(v) > 254 or not _EMAIL_RE.match(v):
            raise ValueError('invalid email format')
        return v

    @field_validator('password')
    @classmethod
    def _validate_password(cls, v):
        # Validate only — never mutate/strip a password.
        if not isinstance(v, str) or _CONTROL_CHARS_RE.search(v):
            raise ValueError('password contains invalid characters')
        if not (8 <= len(v) <= 128):
            raise ValueError('password must be 8-128 characters')
        if not (re.search(r'[A-Za-z]', v) and re.search(r'\d', v)):
            raise ValueError('password must contain letters and numbers')
        return v

    @field_validator('display_name')
    @classmethod
    def _validate_display_name(cls, v):
        if v is None:
            return v
        v = sanitize_text(v)
        if v == '':
            return None
        if not _DISPLAY_NAME_RE.match(v):
            raise ValueError('display name contains invalid characters')
        return v


class LoginSchema(BaseModel):
    """Validation schema for POST /api/auth/login.

    Intentionally lenient on the password (no complexity/format rules) so existing
    accounts can always authenticate; it only caps length to prevent resource
    exhaustion and sanitizes the username for defense in depth.
    """
    model_config = {'extra': 'ignore'}

    username: str
    password: str

    @field_validator('username')
    @classmethod
    def _validate_username(cls, v):
        v = sanitize_text(v)
        if not _USERNAME_RE.match(v):
            raise ValueError('invalid username')
        return v

    @field_validator('password')
    @classmethod
    def _validate_password(cls, v):
        if not isinstance(v, str) or not (1 <= len(v) <= 128):
            raise ValueError('invalid password')
        return v


def _log_validation_failure(route, err, remote_addr):
    """Log validation failures for monitoring — field names + error types only.

    Never logs submitted values, so passwords/emails never reach the log.
    """
    fields = sorted({'.'.join(str(p) for p in e['loc']) for e in err.errors()})
    types = sorted({e['type'] for e in err.errors()})
    logger.warning(
        "Auth input validation failure on %s from %s — fields=%s types=%s",
        route, remote_addr or 'unknown', fields, types)


# ============ API ROUTES ============


@app.route('/')
def serve_index():
    """Serve the SPA HTML with a cache-busting version stamp on app.js and app.css.

    The browser caches static files aggressively; without a version query string
    every server-side edit to app.js is invisible until the user manually hard-
    refreshes (Ctrl+Shift+R).  Injecting ?v=<timestamp> at request time forces
    a fresh fetch whenever the server restarts.
    """
    import time
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             'vuln-scanner-app.html')
    with open(html_path, 'r', encoding='utf-8') as f:
        html = f.read()
    # Stamp both static assets so edits are immediately visible after restart
    stamp = int(time.time())
    html = html.replace('src="static/app.js"',
                        f'src="static/app.js?v={stamp}"')
    html = html.replace("src='static/app.js'",
                        f"src='static/app.js?v={stamp}'")
    html = html.replace('href="static/app.css"',
                        f'href="static/app.css?v={stamp}"')
    html = html.replace("href='static/app.css'",
                        f"href='static/app.css?v={stamp}'")
    from flask import Response
    return Response(html, mimetype='text/html',
                    headers={'Cache-Control': 'no-store'})



@app.route('/api/auth/register', methods=['POST'])
def register():
    # Server-side validation/sanitization — runs regardless of client-side checks.
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        payload = {}
    try:
        data = RegisterSchema(**payload)
    except ValidationError as e:
        _log_validation_failure('/api/auth/register', e, request.remote_addr)
        err_msgs = []
        for err in e.errors():
            loc = err['loc']
            field = loc[0] if loc else 'input'
            msg = err['msg']
            if msg.startswith("Value error, "):
                msg = msg[len("Value error, "):]
            err_msgs.append(f"{field}: {msg}")
        try:
            db.session.add(AuditLog(event_type='validation_fail', ip_address=request.remote_addr,
                                    details=f"Registration validation failed: {', '.join(err_msgs)}"))
            db.session.commit()
        except Exception as _e:
            db.session.rollback()
        return jsonify({'error': f"Validation failed: {', '.join(err_msgs)}"}), 400

    # Operate only on sanitized/validated values from here on.
    # The success body is identical whether or not the email already exists, so the
    # response can never be used to confirm that an email is registered.
    success_msg = ('Registration successful. You can now log in.'
                   if not REQUIRE_EMAIL_VERIFICATION
                   else 'Registration successful. Please verify your email address before logging in.')

    if User.query.filter_by(email=data.email).first() is not None:
        # Email already registered -> respond EXACTLY like a fresh signup, create
        # nothing, send nothing. Burn an equivalent bcrypt cost so the masked path
        # isn't a faster (timing-distinguishable) branch than a real signup.
        bcrypt.check_password_hash(_DUMMY_HASH, data.password)
        logger.info(
            "Registration masked: email already registered (no enumeration disclosed)")
        try:
            db.session.add(AuditLog(event_type='validation_fail', ip_address=request.remote_addr,
                                    details="Registration attempt on an already-registered email (masked)"))
            db.session.commit()
        except Exception as _e:
            db.session.rollback()
        return jsonify({'message': success_msg}), 201

    if User.query.filter_by(username=data.username).first() is not None:
        # A username collision is not email enumeration; report it generically.
        logger.info("Registration conflict: username taken")
        try:
            db.session.add(AuditLog(event_type='validation_fail', ip_address=request.remote_addr,
                                    details=f"Registration conflict: username '{data.username}' is taken"))
            db.session.commit()
        except Exception as _e:
            db.session.rollback()
        return jsonify({'error': 'That username is unavailable. Please choose another.'}), 409

    # When verification is disabled, the account is usable immediately (no email gate).
    user = User(username=data.username, email=data.email,
                display_name=data.display_name,
                email_verified=not REQUIRE_EMAIL_VERIFICATION)
    user.set_password(data.password)
    db.session.add(user)
    try:
        _detail = ("New user registered successfully (pending email verification)"
                   if REQUIRE_EMAIL_VERIFICATION else "New user registered successfully")
        db.session.add(AuditLog(event_type='user_created', username=data.username,
                                ip_address=request.remote_addr, details=_detail))
    except Exception as _e:
        pass
    db.session.commit()

    if REQUIRE_EMAIL_VERIFICATION:
        # Dispatch verification email asynchronously (best-effort; no-op without SMTP).
        threading.Thread(target=_send_verification_email,
                         args=(user.id,), daemon=True).start()

    resp = {'message': success_msg}
    # Dev convenience: with no SMTP configured, surface the link so verification is
    # still reachable. Never exposed in production or once SMTP is set up.
    if REQUIRE_EMAIL_VERIFICATION and not _IS_PRODUCTION and not SMTP_HOST:
        resp['verify_url'] = _verification_link(user.id)
    return jsonify(resp), 201


@app.route('/api/auth/login', methods=['POST'])
# outermost gate: enforce 10/IP/min (429) before any account logic
@rate_limit_login
def login():
    ip = _client_ip()

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        payload = {}
    try:
        data = LoginSchema(**payload)
    except ValidationError as e:
        _log_validation_failure('/api/auth/login', e, request.remote_addr)
        try:
            db.session.add(AuditLog(event_type='validation_fail', ip_address=ip,
                                    details="Login validation failed"))
            db.session.commit()
        except Exception:
            db.session.rollback()
        # Route malformed input through the SAME delayed, bcrypt-equalized 401 so it
        # isn't a faster, distinguishable path than a real wrong-password attempt.
        return _login_reject(password='', delay=_delay_for(_record_ip_failure(ip)),
                             did_bcrypt=False)

    username = data.username

    # Always run bcrypt (real hash for a real user, dummy hash otherwise) so the
    # unknown-user branch costs the same as a wrong-password branch — no enumeration.
    user = User.query.filter_by(username=username).first()
    if user is not None:
        pw_ok = user.check_password(data.password)
        if pw_ok and not user.is_active:
            try:
                db.session.add(AuditLog(event_type='login_fail', username=username, ip_address=ip,
                                        details="Login rejected: account is temporarily disabled"))
                db.session.commit()
            except Exception:
                pass
            return jsonify({'error': 'Your account has been temporarily disabled.'}), 403

        if REQUIRE_EMAIL_VERIFICATION and pw_ok and not user.email_verified:
            try:
                db.session.add(AuditLog(event_type='login_fail', username=username, ip_address=ip,
                                        details="Login rejected: email not verified"))
                db.session.commit()
            except Exception:
                pass
            return jsonify({'error': 'Please verify your email address before logging in.'}), 403
    else:
        bcrypt.check_password_hash(_DUMMY_HASH, data.password)
        pw_ok = False

    # Admission is atomic: succeeds only if the password is correct AND the account is
    # not locked. A correct password on a LOCKED account still fails (lockout precedence).
    if pw_ok and _try_admit(username):
        _reset_ip_failures(ip)
        user.last_login = datetime.utcnow()
        try:
            db.session.add(AuditLog(event_type='login_success', username=username, ip_address=ip,
                                    details="User signed in successfully"))
        except Exception:
            pass
        db.session.commit()
        from flask_jwt_extended import create_refresh_token
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        return jsonify({'token': access_token, 'refresh_token': refresh_token, 'user': user.to_dict()})

    # Unified failure path: wrong password, unknown user, AND correct-but-locked all
    # converge here, becoming indistinguishable in body, status, and timing. The delay
    # is keyed on the requester's IP (not the account), so it never leaks lock state.
    should_email = _record_failure(username, ip)
    try:
        db.session.add(AuditLog(event_type='login_fail', username=username, ip_address=ip,
                                details="Failed sign-in attempt"))
        if should_email:
            db.session.add(AuditLog(event_type='lockout', username=username, ip_address=ip,
                                    details="Account locked due to 5 consecutive failures"))
        db.session.commit()
    except Exception:
        db.session.rollback()

    if should_email and user is not None:
        # Real OS thread (not a greenlet): blocking SMTP can't stall the eventlet hub.
        threading.Thread(target=_send_lockout_email,
                         args=(user.id,), daemon=True).start()
    delay = _delay_for(_record_ip_failure(ip))
    return _login_reject(password=data.password, delay=delay, did_bcrypt=True)


@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()

    user = User.query.get(user_id)

    if user is None:
        return jsonify({
            "error": "User not found",
            "user_id": user_id
        }), 404

    return jsonify({
        "user": user.to_dict()
    }), 200


@app.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    """Issue a new short-lived access token using the long-lived refresh token.
    The refresh token is verified by flask-jwt-extended; on success a fresh
    access token is returned so the client can stay logged in silently."""
    from flask_jwt_extended import jwt_required as _jwt_required, create_refresh_token, get_jwt_identity as _get_identity
    from flask_jwt_extended import verify_jwt_in_request
    try:
        verify_jwt_in_request(refresh=True)
    except Exception as e:
        return jsonify({'error': 'Invalid or expired refresh token'}), 401
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or not user.is_active:
        return jsonify({'error': 'Account not found or disabled'}), 401
    new_access = create_access_token(identity=user_id)
    return jsonify({'token': new_access})


class ChangePasswordSchema(BaseModel):
    """Validation schema for POST /api/auth/change-password."""
    model_config = {'extra': 'ignore'}

    current_password: str
    new_password: str

    @field_validator('current_password')
    @classmethod
    def _validate_current(cls, v):
        # Validate length only — never mutate/strip, never reveal specifics.
        if not isinstance(v, str) or not (1 <= len(v) <= 128):
            raise ValueError('invalid current password')
        return v

    @field_validator('new_password')
    @classmethod
    def _validate_new(cls, v):
        # Same strength policy as registration.
        if not isinstance(v, str) or _CONTROL_CHARS_RE.search(v):
            raise ValueError('password contains invalid characters')
        if not (8 <= len(v) <= 128):
            raise ValueError('password must be 8-128 characters')
        if not (re.search(r'[A-Za-z]', v) and re.search(r'\d', v)):
            raise ValueError('password must contain letters and numbers')
        return v


@app.route('/api/auth/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Change the authenticated user's password. Verifies the current password
    (constant-time), then re-hashes the new one with bcrypt(>=12). Passwords are
    never logged. A correct current password also upgrades any legacy hash."""
    user = User.query.get(get_jwt_identity())
    if user is None:
        return jsonify({'error': 'Unable to process this request'}), 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        payload = {}
    try:
        data = ChangePasswordSchema(**payload)
    except ValidationError as e:
        _log_validation_failure(
            '/api/auth/change-password', e, request.remote_addr)
        # Generic message — don't reveal which rule failed.
        return jsonify({'error': 'Password does not meet requirements'}), 400

    # Verify the current password (constant-time; also migrates a legacy hash).
    if not user.check_password(data.current_password):
        try:
            db.session.add(AuditLog(event_type='password_change_fail', username=user.username,
                                    ip_address=request.remote_addr,
                                    details="Password change rejected: current password incorrect"))
            db.session.commit()
        except Exception:
            db.session.rollback()
        return jsonify({'error': 'Current password is incorrect'}), 403

    # Reject a no-op change (constant-time compare of the two supplied values).
    if secrets.compare_digest(data.new_password, data.current_password):
        return jsonify({'error': 'New password must be different from the current password'}), 400

    user.set_password(data.new_password)   # re-hash with bcrypt(>=12)
    # Clear the forced-change flag so the first-login modal doesn't re-appear.
    user.must_change_password = False
    try:
        db.session.add(AuditLog(event_type='password_change', username=user.username,
                                ip_address=request.remote_addr,
                                details="Password changed successfully"))
    except Exception:
        pass
    db.session.commit()
    logger.info("Password changed for user id=%s", user.id)
    return jsonify({'message': 'Password updated successfully.'}), 200


@app.route('/api/auth/verify-email', methods=['GET'])
def verify_email():
    token = request.args.get('token')
    if not token:
        return "Missing verification token", 400
    try:
        data = _verify_serializer.loads(token, max_age=3600)  # 1 hour expiry
        user_id = data.get('uid')
        user = User.query.get(user_id)
        if not user:
            return "Invalid or expired verification link", 400
        if user.email_verified:
            return _verified_success_page(already=True)

        user.email_verified = True
        try:
            db.session.add(AuditLog(event_type='email_verified', username=user.username, ip_address=request.remote_addr,
                                    details="Email verified successfully"))
        except Exception:
            pass
        db.session.commit()

        return _verified_success_page(already=False)
    except Exception as e:
        logger.error("Email verification token error: %s", e)
        return "Invalid or expired verification token", 400


@app.route('/api/auth/resend-verification', methods=['POST'])
@rate_limit_login  # reuse the per-IP 10/min limiter to bound email-bombing
def resend_verification():
    """Re-send the verification link for an unverified account — the recovery path
    for a lost email or an expired (1-hour) token. Always returns the same generic
    200 so it can't be used to enumerate which emails are registered/verified."""
    payload = request.get_json(silent=True) or {}
    email = sanitize_text(str(payload.get('email', ''))).lower()
    resp = {'message': 'If an unverified account exists for that email, '
                       'a new verification link has been sent.'}
    if _EMAIL_RE.match(email):
        user = User.query.filter_by(email=email).first()
        if user and not user.email_verified:
            logger.info("Resending verification email uid=%s", user.id)
            threading.Thread(target=_send_verification_email,
                             args=(user.id,), daemon=True).start()
            # Dev convenience only (never in production / once SMTP is configured).
            if not _IS_PRODUCTION and not SMTP_HOST:
                resp['verify_url'] = _verification_link(user.id)
    return jsonify(resp), 200


# ============ ADMIN ROUTES ============

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])


@app.route('/api/admin/users/<user_id>', methods=['PUT'])
@admin_required
def admin_update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    if not data:
        data = {}

    # Track original state for logging
    old_role = user.role
    old_active = user.is_active
    old_verified = user.email_verified

    if 'role' in data:
        user.role = data['role']
    if 'is_active' in data:
        user.is_active = bool(data['is_active'])
    if 'email_verified' in data:
        user.email_verified = bool(data['email_verified'])

    db.session.commit()

    # Log user update event
    try:
        details = []
        if user.role != old_role:
            details.append(f"role: {old_role} -> {user.role}")
        if user.is_active != old_active:
            details.append(f"active: {old_active} -> {user.is_active}")
        if user.email_verified != old_verified:
            details.append(
                f"verified: {old_verified} -> {user.email_verified}")

        details_msg = f"Updated user '{user.username}': {', '.join(details)}" if details else f"No changes to user '{user.username}'"
        db.session.add(AuditLog(event_type='user_update', username=user.username, ip_address=request.remote_addr,
                                details=details_msg))
        db.session.commit()
    except Exception:
        pass

    return jsonify(user.to_dict())


@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == 'admin':
        return jsonify({'error': 'Cannot delete primary admin user'}), 400

    try:
        db.session.add(AuditLog(event_type='user_delete', username=user.username, ip_address=request.remote_addr,
                                details=f"Admin deleted user '{user.username}'"))
    except Exception:
        pass

    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})


@app.route('/api/admin/logs', methods=['GET'])
@admin_required
def admin_get_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return jsonify([l.to_dict() for l in logs])


@app.route('/api/admin/config', methods=['GET'])
@admin_required
def admin_get_config():
    # Return current rate limiting and security status
    return jsonify({
        'LOGIN_RL_MAX': RL_MAX,
        'LOGIN_RL_WINDOW_SEC': RL_WINDOW,
        'LOGIN_LOCK_THRESHOLD': LOCK_THRESHOLD,
        'LOGIN_LOCK_DURATION_SEC': LOCK_DURATION,
        'SMTP_CONFIGURED': bool(SMTP_HOST),
        'SMTP_HOST': SMTP_HOST or 'Unconfigured',
        'APP_BASE_URL': APP_BASE_URL
    })


@app.route('/api/admin/config', methods=['PUT'])
@admin_required
def admin_update_config():
    global RL_MAX, RL_WINDOW, LOCK_THRESHOLD, LOCK_DURATION
    data = request.get_json()
    if not data:
        data = {}

    try:
        updated_fields = []
        if 'LOGIN_RL_MAX' in data:
            val = int(data['LOGIN_RL_MAX'])
            if val <= 0:
                raise ValueError("Rate limit max must be positive")
            RL_MAX = val
            updated_fields.append(f"RL_MAX={RL_MAX}")

        if 'LOGIN_RL_WINDOW_SEC' in data:
            val = int(data['LOGIN_RL_WINDOW_SEC'])
            if val <= 0:
                raise ValueError("Rate limit window must be positive")
            RL_WINDOW = val
            updated_fields.append(f"RL_WINDOW={RL_WINDOW}")

        if 'LOGIN_LOCK_THRESHOLD' in data:
            val = int(data['LOGIN_LOCK_THRESHOLD'])
            if val <= 0:
                raise ValueError("Lockout threshold must be positive")
            LOCK_THRESHOLD = val
            updated_fields.append(f"LOCK_THRESHOLD={LOCK_THRESHOLD}")

        if 'LOGIN_LOCK_DURATION_SEC' in data:
            val = int(data['LOGIN_LOCK_DURATION_SEC'])
            if val <= 0:
                raise ValueError("Lockout duration must be positive")
            LOCK_DURATION = val
            updated_fields.append(f"LOCK_DURATION={LOCK_DURATION}")

        if updated_fields:
            admin_username = get_jwt_identity()
            admin_user = User.query.get(admin_username)
            user_name = admin_user.username if admin_user else 'admin'

            db.session.add(AuditLog(
                event_type='config_update',
                username=user_name,
                ip_address=request.remote_addr,
                details=f"Updated security settings: {', '.join(updated_fields)}"
            ))
            db.session.commit()

    except (ValueError, TypeError) as e:
        return jsonify({'error': f'Invalid value: {str(e)}'}), 400

    return jsonify({
        'LOGIN_RL_MAX': RL_MAX,
        'LOGIN_RL_WINDOW_SEC': RL_WINDOW,
        'LOGIN_LOCK_THRESHOLD': LOCK_THRESHOLD,
        'LOGIN_LOCK_DURATION_SEC': LOCK_DURATION,
        'SMTP_CONFIGURED': bool(SMTP_HOST),
        'SMTP_HOST': SMTP_HOST or 'Unconfigured',
        'APP_BASE_URL': APP_BASE_URL
    })


@app.route('/api/projects', methods=['GET'])
@jwt_required()
def get_projects():
    user_id = get_jwt_identity()
    projects = Project.query.filter_by(user_id=user_id).all()
    return jsonify([p.to_dict() for p in projects])


@app.route('/api/projects', methods=['POST'])
@jwt_required()
def create_project():
    user_id = get_jwt_identity()
    data = request.get_json()
    project = Project(name=data['name'], description=data.get(
        'description', ''), user_id=user_id)
    db.session.add(project)
    try:
        user = User.query.get(user_id)
        db.session.add(AuditLog(event_type='project_create', username=user.username if user else 'unknown',
                                ip_address=request.remote_addr, details=f"Created project '{project.name}'"))
    except Exception:
        pass
    db.session.commit()
    return jsonify(project.to_dict()), 201


@app.route('/api/projects/<project_id>', methods=['PUT'])
@jwt_required()
def update_project(project_id):
    project = Project.query.get_or_404(project_id)
    data = request.get_json()
    project.name = data.get('name', project.name)
    project.description = data.get('description', project.description)
    db.session.commit()
    return jsonify(project.to_dict())


@app.route('/api/projects/<project_id>', methods=['DELETE'])
@jwt_required()
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    try:
        user = User.query.get(get_jwt_identity())
        db.session.add(AuditLog(event_type='project_delete', username=user.username if user else 'unknown',
                                ip_address=request.remote_addr, details=f"Deleted project '{project.name}'"))
    except Exception:
        pass
    db.session.delete(project)
    db.session.commit()
    return jsonify({'message': 'Project deleted'})


@app.route('/api/projects/<project_id>/targets', methods=['GET'])
@jwt_required()
def get_targets(project_id):
    targets = Target.query.filter_by(project_id=project_id).all()
    return jsonify([t.to_dict() for t in targets])


@app.route('/api/targets', methods=['POST'])
@jwt_required()
def create_target():
    data = request.get_json()
    target = Target(url=data['url'], name=data.get('name', ''),
                    description=data.get('description', ''), project_id=data['project_id'])
    db.session.add(target)
    try:
        user = User.query.get(get_jwt_identity())
        db.session.add(AuditLog(event_type='target_create', username=user.username if user else 'unknown',
                                ip_address=request.remote_addr, details=f"Added target '{target.url}' to project ID '{target.project_id}'"))
    except Exception:
        pass
    db.session.commit()
    return jsonify(target.to_dict()), 201


@app.route('/api/targets/<target_id>', methods=['DELETE'])
@jwt_required()
def delete_target(target_id):
    target = Target.query.get_or_404(target_id)
    try:
        user = User.query.get(get_jwt_identity())
        db.session.add(AuditLog(event_type='target_delete', username=user.username if user else 'unknown',
                                ip_address=request.remote_addr, details=f"Deleted target '{target.url}'"))
    except Exception:
        pass
    db.session.delete(target)
    db.session.commit()
    return jsonify({'message': 'Target deleted'})


@app.route('/api/scans', methods=['POST'])
@jwt_required()
def start_scan():
    data = request.get_json()
    target = Target.query.get_or_404(data['target_id'])
    scan = Scan(target_id=target.id, config=json.dumps(data.get('config', {})))
    db.session.add(scan)
    try:
        user = User.query.get(get_jwt_identity())
        db.session.add(AuditLog(event_type='scan_start', username=user.username if user else 'unknown',
                                ip_address=request.remote_addr, details=f"Started scan on target '{target.url}' (Scan ID: {scan.id})"))
    except Exception:
        pass
    db.session.commit()
    # Start scan via Celery (if REDIS_URL configured) or a background thread.
    dispatch_scan(scan.id, target.url, data.get('config', {}))
    return jsonify(scan.to_dict()), 201


@app.route('/api/scans/<scan_id>', methods=['DELETE'])
@jwt_required()
def cancel_scan(scan_id):
    """Request cancellation of a running scan. The scanner thread checks
    _cancelled_scans on each iteration and exits gracefully."""
    scan = Scan.query.get_or_404(scan_id)
    if scan.status not in ('pending', 'running'):
        return jsonify({'error': f'Scan is already {scan.status}'}), 400
    with _cancel_lock:
        _cancelled_scans.add(scan_id)
    logger.info("Scan cancellation requested: %s", scan_id)
    return jsonify({'message': 'Cancellation requested', 'scan_id': scan_id})


@app.route('/api/scans/<scan_id>', methods=['GET'])
@jwt_required()
def get_scan(scan_id):
    # Expire ALL objects in this session so SQLAlchemy re-reads from the DB.
    # Without this, the identity map returns a cached copy with stale progress
    # when the background task has committed new values in its own session.
    db.session.expire_all()
    scan = Scan.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())


@app.route('/api/targets/<target_id>/scans', methods=['GET'])
@jwt_required()
def get_target_scans(target_id):
    """Return all scans for a target, ordered newest-first."""
    Target.query.get_or_404(target_id)  # 404 guard
    scans = (Scan.query
             .filter_by(target_id=target_id)
             .order_by(Scan.started_at.desc())
             .all())
    return jsonify([s.to_dict() for s in scans])


@app.route('/api/scans/<scan_id>/diff/<prev_scan_id>', methods=['GET'])
@jwt_required()
def diff_scans(scan_id, prev_scan_id):
    """Compare two scans for the same target. Returns new, fixed, and persistent findings."""
    current_vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()
    prev_vulns = Vulnerability.query.filter_by(scan_id=prev_scan_id).all()

    def _key(v):
        return (v.vuln_type, (v.affected_url or '').rstrip('/'), v.parameter or '')

    current_keys = {_key(v): v.to_dict() for v in current_vulns}
    prev_keys = {_key(v): v.to_dict() for v in prev_vulns}

    new_findings = [v for k, v in current_keys.items() if k not in prev_keys]
    fixed_findings = [v for k, v in prev_keys.items() if k not in current_keys]
    persistent = [v for k, v in current_keys.items() if k in prev_keys]

    return jsonify({
        'scan_id': scan_id,
        'prev_scan_id': prev_scan_id,
        'new': new_findings,
        'fixed': fixed_findings,
        'persistent': persistent,
        'summary': {
            'new_count': len(new_findings),
            'fixed_count': len(fixed_findings),
            'persistent_count': len(persistent)
        }
    })


@app.route('/api/scans/<scan_id>/vulnerabilities', methods=['GET'])
@jwt_required()
def get_vulnerabilities(scan_id):
    vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()
    return jsonify([v.to_dict() for v in vulns])


@app.route('/api/scans/<scan_id>/report/pdf', methods=['GET'])
@jwt_required()
def download_pdf_report(scan_id):
    from flask import send_file
    import io
    pdf_data = ReportGenerator.generate_pdf(scan_id)
    if not pdf_data:
        return jsonify({'error': 'Scan not found'}), 404
    return send_file(io.BytesIO(pdf_data), mimetype='application/pdf',
                     as_attachment=True, download_name=f'vuln-report-{scan_id[:8]}.pdf')


@app.route('/api/scans/<scan_id>/report/json', methods=['GET'])
@jwt_required()
def download_json_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    vulns = Vulnerability.query.filter_by(scan_id=scan_id).all()
    report = {'scan': scan.to_dict(), 'vulnerabilities': [v.to_dict() for v in vulns],
              'generated_at': datetime.utcnow().isoformat()}
    return jsonify(report)


@app.route('/api/scans', methods=['GET'])
@jwt_required()
def get_all_scans():
    user_id = get_jwt_identity()
    scans = (Scan.query
             .join(Target)
             .join(Project)
             .filter(Project.user_id == user_id)
             .order_by(Scan.started_at.desc())
             .all())
    return jsonify([s.to_dict() for s in scans])


@app.route('/api/vulnerabilities', methods=['GET'])
@jwt_required()
def get_all_vulnerabilities():
    user_id = get_jwt_identity()
    vulns = (Vulnerability.query
             .join(Scan)
             .join(Target)
             .join(Project)
             .filter(Project.user_id == user_id)
             .all())
    return jsonify([v.to_dict() for v in vulns])


@app.route('/api/schedules', methods=['GET'])
@jwt_required()
def get_schedules():
    user_id = get_jwt_identity()
    schedules = (ScheduledScan.query
                 .join(Target)
                 .join(Project)
                 .filter(Project.user_id == user_id)
                 .all())
    return jsonify([s.to_dict() for s in schedules])


@app.route('/api/schedules', methods=['POST'])
@jwt_required()
def create_schedule():
    user_id = get_jwt_identity()
    data = request.get_json()
    target = Target.query.get_or_404(data['target_id'])
    if target.project.user_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403

    schedule = ScheduledScan(
        target_id=target.id,
        cron_expression=data['cron_expression']
    )
    db.session.add(schedule)
    db.session.commit()
    return jsonify(schedule.to_dict()), 201


@app.route('/api/schedules/<schedule_id>', methods=['DELETE'])
@jwt_required()
def delete_schedule(schedule_id):
    user_id = get_jwt_identity()
    schedule = ScheduledScan.query.get_or_404(schedule_id)
    if schedule.target.project.user_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403

    db.session.delete(schedule)
    db.session.commit()
    return jsonify({'message': 'Schedule deleted'})


def is_cron_due(cron_expr, dt):
    """Lite helper to evaluate standard cron expression elements (*, commas, step, ranges)"""
    parts = cron_expr.split()
    if len(parts) != 5:
        return False
    minute, hour, dom, month, dow = parts

    def match_part(value, part):
        if part == '*':
            return True
        if ',' in part:
            return any(match_part(value, p) for p in part.split(','))
        if '/' in part:
            p, step = part.split('/')
            step_val = int(step)
            if p == '*':
                return value % step_val == 0
            else:
                start = int(p)
                return value >= start and (value - start) % step_val == 0
        if '-' in part:
            start, end = part.split('-')
            return int(start) <= value <= int(end)
        return int(part) == value

    cron_dow = dt.isoweekday() % 7  # 0 (Sun) to 6 (Sat)
    try:
        return (match_part(dt.minute, minute) and
                match_part(dt.hour, hour) and
                match_part(dt.day, dom) and
                match_part(dt.month, month) and
                match_part(cron_dow, dow))
    except Exception:
        return False


def start_scheduled_scan_worker(app_instance, socketio_instance):
    """Background worker loop that evaluates scheduled scans every minute."""
    logger.info("Starting scheduled scan background worker...")
    import time
    while True:
        try:
            time.sleep(60)
            now = datetime.utcnow()
            with app_instance.app_context():
                schedules = ScheduledScan.query.filter_by(enabled=True).all()
                for sched in schedules:
                    if is_cron_due(sched.cron_expression, now):
                        if sched.last_run and (now - sched.last_run).total_seconds() < 50:
                            continue
                        logger.info(
                            "Triggering scheduled scan for target: %s", sched.target.url)
                        sched.last_run = now
                        scan = Scan(target_id=sched.target_id,
                                    config=json.dumps({"scheduled": True}))
                        db.session.add(scan)
                        db.session.commit()
                        # Same dispatch path as the API: Celery when configured, else a thread.
                        dispatch_scan(scan.id, sched.target.url,
                                      {"scheduled": True})
        except Exception as e:
            logger.warning("Error in scheduled scan background worker: %s", e)
            time.sleep(10)


@app.route('/api/dashboard/stats', methods=['GET'])
@jwt_required()
def get_dashboard_stats():
    user_id = get_jwt_identity()
    projects = Project.query.filter_by(user_id=user_id).all()
    project_ids = [p.id for p in projects]
    targets = Target.query.filter(Target.project_id.in_(project_ids)).all()
    target_ids = [t.id for t in targets]
    scans = Scan.query.filter(Scan.target_id.in_(target_ids)).all()
    scan_ids = [s.id for s in scans]
    vulns = Vulnerability.query.filter(
        Vulnerability.scan_id.in_(scan_ids)).all()
    severity_breakdown = {'critical': 0, 'high': 0,
                          'medium': 0, 'low': 0, 'info': 0}
    for v in vulns:
        severity_breakdown[v.severity] = severity_breakdown.get(
            v.severity, 0) + 1
    return jsonify({
        'total_projects': len(projects), 'total_targets': len(targets),
        'total_scans': len(scans), 'total_vulnerabilities': len(vulns),
        'severity_breakdown': severity_breakdown,
        'recent_scans': [s.to_dict() for s in sorted(scans, key=lambda x: x.started_at or datetime.min, reverse=True)[:5]]
    })

# ============ ZAP PROXY API ROUTES ==========================================
# ALL ZAP communication happens here — inside Flask.
# The browser NEVER sees ZAP_API_URL, ZAP_API_KEY, or port 8080.
# Every endpoint requires a valid JWT token.


def _zap_unavailable_response():
    """Standard 503 returned when ZAP is not configured or unreachable."""
    return jsonify({
        'status': 'error',
        'code': 'ZAP_NOT_CONFIGURED',
        'message': (
            'OWASP ZAP integration is not configured on this server. '
            'Set ZAP_API_URL and ZAP_API_KEY environment variables and '
            'ensure the Cloudflare tunnel is running.'
        ),
    }), 503


@app.route('/api/zap/health', methods=['GET'])
@jwt_required()
def zap_health():
    """
    GET /api/zap/health
    Quick liveness check — is ZAP reachable through the Cloudflare tunnel?

    Response 200:
        { "status": "ok", "zap_reachable": true, "zap_version": "2.15.0" }
    Response 503:
        { "status": "error", "zap_reachable": false, "message": "..." }
    """
    if not zap_service.is_configured():
        return jsonify({
            'status': 'error',
            'zap_reachable': False,
            'message': 'ZAP_API_URL is not configured.',
        }), 503
    result = zap_service.check_zap_availability()
    http_status = 200 if result['reachable'] else 503
    return jsonify({
        'status': 'ok' if result['reachable'] else 'error',
        'zap_reachable': result['reachable'],
        'zap_version': result.get('version'),
        'message': result.get('message'),
    }), http_status


@app.route('/api/zap/status', methods=['GET'])
@jwt_required()
def zap_status():
    """
    GET /api/zap/status
    Detailed ZAP status: version, operating mode, alerts in current session.
    ZAP_API_URL and ZAP_API_KEY are NEVER included in this response.

    Response 200:
        { "status": "ok", "zap_reachable": true, "zap_version": "...",
          "zap_mode": "standard", "alerts_in_session": 0 }
    """
    if not zap_service.is_configured():
        return _zap_unavailable_response()
    info = zap_service.get_zap_info()
    return jsonify({
        'status': 'ok' if info.get('reachable') else 'error',
        'zap_reachable':      info.get('reachable', False),
        'zap_version':        info.get('version'),
        'zap_mode':           info.get('mode'),
        'alerts_in_session':  info.get('alerts_in_session', 0),
        'message':            info.get('message'),
    })


@app.route('/api/zap/scan/start', methods=['POST'])
@jwt_required()
def zap_scan_start():
    """
    POST /api/zap/scan/start
    Start a full ZAP scan (spider → passive → active) on a target.

    Request body:
        { "target_id": "<uuid>", "scan_type": "full" }

    Response 201:
        { "scan_id": "<uuid>", "status": "started", "target_url": "..." }
    Response 400 / 503:
        { "status": "error", "message": "..." }
    """
    if not zap_service.is_configured():
        return _zap_unavailable_response()

    user_id = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    target_id = data.get('target_id', '').strip()
    if not target_id:
        return jsonify({'status': 'error', 'message': 'target_id is required.'}), 400

    target = Target.query.get(target_id)
    if not target:
        return jsonify({'status': 'error', 'message': 'Target not found.'}), 404

    # Ownership check
    if target.project.user_id != user_id:
        return jsonify({'status': 'error', 'message': 'Access denied.'}), 403

    # URL validation (before sending to ZAP)
    valid, reason = zap_service.validate_scan_target(target.url)
    if not valid:
        return jsonify({'status': 'error', 'message': f'Invalid target URL: {reason}'}), 400

    # Quick ZAP reachability check before creating the DB record
    availability = zap_service.check_zap_availability()
    if not availability['reachable']:
        return jsonify({
            'status': 'error',
            'code': 'ZAP_UNREACHABLE',
            'message': f'ZAP is not reachable: {availability["message"]}',
        }), 503

    # Create Scan record
    scan = Scan(
        target_id=target.id,
        config=json.dumps(data.get('config', {})),
        scan_engine='zap',
    )
    db.session.add(scan)
    try:
        user = User.query.get(user_id)
        db.session.add(AuditLog(
            event_type='zap_scan_start',
            username=user.username if user else 'unknown',
            ip_address=request.remote_addr,
            details=f"ZAP scan started on target '{target.url}' (Scan ID: {scan.id})",
        ))
    except Exception:
        pass
    db.session.commit()

    # Dispatch to background thread
    dispatch_zap_scan(scan.id, target.url, data.get('config', {}))

    logger.info('[ZAP] Scan %s dispatched for target %r (user %s)',
                scan.id[:8], target.url, user_id)
    return jsonify({
        'status': 'started',
        'scan_id': scan.id,
        'target_url': target.url,
        'scan_engine': 'zap',
    }), 201


@app.route('/api/zap/scan/stop/<scan_id>', methods=['POST'])
@jwt_required()
def zap_scan_stop(scan_id):
    """
    POST /api/zap/scan/stop/<scan_id>
    Request cancellation of a running ZAP scan.
    Adds the scan_id to the shared _cancelled_scans set (same mechanism
    used by the native engine cancel endpoint).
    Also sends stop signals directly to ZAP for spider and active scan.

    Response 200:
        { "status": "ok", "message": "Cancellation requested", "scan_id": "..." }
    """
    scan = Scan.query.get_or_404(scan_id)
    if scan.status not in ('pending', 'running'):
        return jsonify({
            'status': 'error',
            'message': f'Scan is already {scan.status}.',
        }), 400

    # Signal the background thread via the shared cancel set
    with _cancel_lock:
        _cancelled_scans.add(scan_id)

    # Send stop directly to ZAP in case the thread is mid-poll
    with _zap_scan_lock:
        state = _zap_active_scans.get(scan_id, {})
    ascan_id = state.get('ascan_id')
    if ascan_id:
        zap_service.stop_active_scan(ascan_id)
    if zap_service.get_ajax_spider_status() == 'running':
        zap_service.stop_ajax_spider()

    logger.info('[ZAP] Cancellation requested for scan %s', scan_id[:8])
    return jsonify({
        'status': 'ok',
        'message': 'Cancellation requested.',
        'scan_id': scan_id,
    })


@app.route('/api/zap/scan/status/<scan_id>', methods=['GET'])
@jwt_required()
def zap_scan_status(scan_id):
    """
    Lightweight live-progress endpoint used by the frontend poller.
    Uses raw SQL to bypass SQLAlchemy's identity map so background-task
    commits are always visible (no stale-cache problem).
    """
    from sqlalchemy import text
    row = db.session.execute(
        text('SELECT status, progress, completed_at FROM scan WHERE id = :id'),
        {'id': scan_id}
    ).fetchone()
    if not row:
        return jsonify({'error': 'Scan not found'}), 404
    # Also count vulns with raw SQL
    vc = db.session.execute(
        text('SELECT COUNT(*) FROM vulnerability WHERE scan_id = :id'),
        {'id': scan_id}
    ).scalar() or 0
    return jsonify({
        'scan_id':    scan_id,
        'status':     row[0],
        'progress':   row[1] or 0,
        'completed':  row[2] is not None,
        'vuln_count': vc,
    })



@app.route('/api/zap/spider/start', methods=['POST'])
@jwt_required()
def zap_spider_start():
    """
    POST /api/zap/spider/start
    Start a ZAP spider scan only (no active scan).

    Request body:
        { "target_url": "https://example.com" }

    Response 200:
        { "status": "ok", "zap_spider_id": "0" }
    """
    if not zap_service.is_configured():
        return _zap_unavailable_response()
    data = request.get_json(silent=True) or {}
    target_url = (data.get('target_url') or '').strip()
    valid, reason = zap_service.validate_scan_target(target_url)
    if not valid:
        return jsonify({'status': 'error', 'message': reason}), 400
    try:
        spider_id = zap_service.start_spider(target_url)
        return jsonify({'status': 'ok', 'zap_spider_id': spider_id})
    except zap_service.ZapError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 502


@app.route('/api/zap/spider/status/<zap_spider_id>', methods=['GET'])
@jwt_required()
def zap_spider_status(zap_spider_id):
    """
    GET /api/zap/spider/status/<zap_spider_id>
    Return spider progress (0–100) for the given ZAP spider scan ID.

    Response 200:
        { "status": "ok", "progress": 45 }
    """
    if not zap_service.is_configured():
        return _zap_unavailable_response()
    try:
        progress = zap_service.get_spider_status(zap_spider_id)
        return jsonify({'status': 'ok', 'progress': progress})
    except zap_service.ZapError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 502


@app.route('/api/zap/ascan/start', methods=['POST'])
@jwt_required()
def zap_ascan_start():
    """
    POST /api/zap/ascan/start
    Start a ZAP active scan only.

    Request body:
        { "target_url": "https://example.com", "scan_policy": "" }

    Response 200:
        { "status": "ok", "zap_ascan_id": "0" }
    """
    if not zap_service.is_configured():
        return _zap_unavailable_response()
    data = request.get_json(silent=True) or {}
    target_url = (data.get('target_url') or '').strip()
    valid, reason = zap_service.validate_scan_target(target_url)
    if not valid:
        return jsonify({'status': 'error', 'message': reason}), 400
    try:
        ascan_id = zap_service.start_active_scan(
            target_url,
            scan_policy=data.get('scan_policy', ''),
        )
        return jsonify({'status': 'ok', 'zap_ascan_id': ascan_id})
    except zap_service.ZapError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 502


@app.route('/api/zap/ascan/status/<zap_ascan_id>', methods=['GET'])
@jwt_required()
def zap_ascan_status(zap_ascan_id):
    """
    GET /api/zap/ascan/status/<zap_ascan_id>
    Return active scan progress (0–100).

    Response 200:
        { "status": "ok", "progress": 72 }
    """
    if not zap_service.is_configured():
        return _zap_unavailable_response()
    try:
        progress = zap_service.get_active_scan_status(zap_ascan_id)
        return jsonify({'status': 'ok', 'progress': progress})
    except zap_service.ZapError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 502


@app.route('/api/zap/pscan/status', methods=['GET'])
@jwt_required()
def zap_pscan_status():
    """
    GET /api/zap/pscan/status
    Return passive scan queue depth. 0 = passive scan complete.

    Response 200:
        { "status": "ok", "records_to_scan": 0 }
    """
    if not zap_service.is_configured():
        return _zap_unavailable_response()
    try:
        remaining = zap_service.get_passive_scan_queue()
        return jsonify({'status': 'ok', 'records_to_scan': remaining})
    except zap_service.ZapError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 502


@app.route('/api/zap/alerts', methods=['GET'])
@jwt_required()
def zap_alerts():
    """
    GET /api/zap/alerts?base_url=https://example.com&risk_level=High
    Fetch raw ZAP alerts from the current session.
    All filtering happens server-side — the ZAP URL is never returned.

    Query params (all optional):
        base_url  — filter to alerts under this URL prefix
        risk_level — 'High' | 'Medium' | 'Low' | 'Informational'

    Response 200:
        { "status": "ok", "count": 15, "alerts": [ {...}, ... ] }
    """
    if not zap_service.is_configured():
        return _zap_unavailable_response()
    base_url = request.args.get('base_url')
    risk_level = request.args.get('risk_level')
    try:
        alerts = zap_service.get_alerts(
            base_url=base_url, risk_level=risk_level
        )
        return jsonify({
            'status': 'ok',
            'count': len(alerts),
            'alerts': alerts,
        })
    except zap_service.ZapError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 502


@app.route('/api/zap/risk_summary', methods=['GET'])
@jwt_required()
def zap_risk_summary():
    """
    GET /api/zap/risk_summary?base_url=https://example.com
    Return a severity-breakdown risk summary computed from ZAP alerts.

    Response 200:
        { "status": "ok", "summary": {
            "critical": 0, "high": 2, "medium": 5,
            "low": 3, "info": 8, "total": 18, "risk_score": 70
          }}
    """
    if not zap_service.is_configured():
        return _zap_unavailable_response()
    base_url = request.args.get('base_url')
    try:
        summary = zap_service.get_risk_summary(base_url=base_url)
        return jsonify({'status': 'ok', 'summary': summary})
    except zap_service.ZapError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 502


@app.route('/api/zap/import_alerts', methods=['POST'])
@jwt_required()
def zap_import_alerts():
    """
    POST /api/zap/import_alerts
    Import the current ZAP session's alerts for a target into the VulnScanPro
    database as Vulnerability records linked to a new Scan row.

    Useful when the user has already run ZAP manually and wants to persist the
    results — no spider or active scan is triggered here.

    Request body:
        { "target_id": "<uuid>" }

    Response 201:
        { "status": "ok", "scan_id": "<uuid>", "imported": 15 }
    """
    if not zap_service.is_configured():
        return _zap_unavailable_response()

    user_id = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    target_id = data.get('target_id', '').strip()
    if not target_id:
        return jsonify({'status': 'error', 'message': 'target_id is required.'}), 400

    target = Target.query.get(target_id)
    if not target:
        return jsonify({'status': 'error', 'message': 'Target not found.'}), 404
    if target.project.user_id != user_id:
        return jsonify({'status': 'error', 'message': 'Access denied.'}), 403

    try:
        alerts = zap_service.get_alerts(base_url=target.url)
    except zap_service.ZapError as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 502

    # Create a completed Scan record to hold the imported results
    scan = Scan(
        target_id=target.id,
        config=json.dumps({'source': 'zap_import'}),
        scan_engine='zap',
        status='completed',
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        progress=100,
        total_urls=len(alerts),
    )
    db.session.add(scan)
    db.session.flush()   # Obtain scan.id before adding Vulnerability rows

    imported = 0
    for alert in alerts:
        vuln_data = zap_service.map_alert_to_vulnerability(alert, scan.id)
        zap_aid = vuln_data.pop('zap_alert_id', None)
        existing = Vulnerability.query.filter_by(
            scan_id=scan.id,
            zap_alert_id=zap_aid or '',
            affected_url=vuln_data.get('affected_url', ''),
        ).first()
        if not existing:
            vuln = Vulnerability(**vuln_data)
            vuln.zap_alert_id = zap_aid
            db.session.add(vuln)
            imported += 1

    try:
        user = User.query.get(user_id)
        db.session.add(AuditLog(
            event_type='zap_import_alerts',
            username=user.username if user else 'unknown',
            ip_address=request.remote_addr,
            details=(
                f"Imported {imported} ZAP alert(s) for target '{target.url}' "
                f"(Scan ID: {scan.id})"
            ),
        ))
    except Exception:
        pass

    db.session.commit()
    logger.info('[ZAP] Imported %d alert(s) for target %r (scan %s)',
                imported, target.url, scan.id[:8])
    return jsonify({
        'status': 'ok',
        'scan_id': scan.id,
        'imported': imported,
        'target_url': target.url,
    }), 201


# ============ END ZAP PROXY API ROUTES =======================================


# WebSocket events


@socketio.on('join_scan')
def on_join_scan(data):
    try:
        scan_id = data.get('scan_id')
        if not scan_id:
            return

        join_room(scan_id)
        logger.info('[Socket.IO] Client joined room: %s', scan_id)

        # ── Catch-up: query the DB directly (we're already in an app context
        # pushed by Flask-SocketIO — no need for a nested with app.app_context()).
        # If the scan is already done (or mid-run) we emit the real state
        # immediately so the UI never stays stuck at 0%.
        try:
            scan = db.session.get(Scan, scan_id)
        except Exception:
            scan = Scan.query.filter_by(id=scan_id).first()

        if scan:
            status   = scan.status   or 'pending'
            progress = scan.progress or 0
            vuln_count = Vulnerability.query.filter_by(scan_id=scan_id).count()

            print(f"[join_scan] scan={scan_id[:8]} status={status} progress={progress} vulns={vuln_count}")

            if status == 'completed':
                msg = f'Scan complete — {vuln_count} finding(s) imported'
                emit('scan_progress', {
                    'scan_id': scan_id,
                    'message': msg,
                    'progress': 100,
                }, room=scan_id)
                print(f"[join_scan] ✅ Sent COMPLETED catch-up (100%)")

            elif status in ('failed', 'cancelled'):
                emit('scan_progress', {
                    'scan_id': scan_id,
                    'message': f'Scan {status}.',
                    'progress': progress,
                }, room=scan_id)
                print(f"[join_scan] ⚠️  Sent {status.upper()} catch-up ({progress}%)")

            elif status == 'running':
                emit('scan_progress', {
                    'scan_id': scan_id,
                    'message': f'Scan in progress… {progress}%',
                    'progress': progress,
                }, room=scan_id)
                print(f"[join_scan] 🔵 Sent RUNNING catch-up ({progress}%)")

            else:
                emit('scan_progress', {
                    'scan_id': scan_id,
                    'message': 'Socket.IO connection established',
                    'progress': 1,
                }, room=scan_id)
                print(f"[join_scan] 🟡 Sent PENDING connection confirmation")
        else:
            print(f"[join_scan] ⚠️  Scan {scan_id[:8]} not found in DB")
            emit('scan_progress', {
                'scan_id': scan_id,
                'message': 'Socket.IO connection established',
                'progress': 1,
            }, room=scan_id)

    except Exception as e:
        logger.error('[Socket.IO] join_scan error: %s', e)
        import traceback; traceback.print_exc()



def ensure_user_schema():
    """Best-effort, idempotent migration: add user.display_name, email_verified,
    and must_change_password to an existing DB.

    db.create_all() only creates missing tables, never alters existing ones, so an
    already-provisioned database needs this to pick up new columns.
    """
    from sqlalchemy import inspect, text
    try:
        columns = {c['name'] for c in inspect(db.engine).get_columns('user')}
        if 'display_name' not in columns:
            db.session.execute(
                text('ALTER TABLE "user" ADD COLUMN display_name VARCHAR(50)'))
            db.session.commit()
            logger.info("Migrated: added user.display_name column")
        if 'email_verified' not in columns:
            db.session.execute(
                text('ALTER TABLE "user" ADD COLUMN email_verified BOOLEAN DEFAULT 0'))
            db.session.execute(
                text('UPDATE "user" SET email_verified = 1'))
            db.session.commit()
            logger.info(
                "Migrated: added user.email_verified column and backfilled existing users")
        if 'must_change_password' not in columns:
            db.session.execute(
                text('ALTER TABLE "user" ADD COLUMN must_change_password BOOLEAN DEFAULT 0'))
            # Existing admin accounts seeded with the default password should also be flagged.
            db.session.execute(
                text("UPDATE \"user\" SET must_change_password = 1 WHERE username = 'admin'"))
            db.session.commit()
            logger.info(
                "Migrated: added user.must_change_password column; flagged admin")
        # ── ZAP integration columns (added in Step 2 migration) ────────────
        scan_cols = {c['name'] for c in inspect(db.engine).get_columns('scan')}
        if 'scan_engine' not in scan_cols:
            db.session.execute(
                text("ALTER TABLE scan ADD COLUMN scan_engine VARCHAR(20) DEFAULT 'native'"))
            db.session.commit()
            logger.info("Migrated: added scan.scan_engine column")
        if 'zap_scan_id' not in scan_cols:
            db.session.execute(
                text('ALTER TABLE scan ADD COLUMN zap_scan_id VARCHAR(50)'))
            db.session.commit()
            logger.info("Migrated: added scan.zap_scan_id column")

        vuln_cols = {c['name']
                     for c in inspect(db.engine).get_columns('vulnerability')}
        if 'zap_alert_id' not in vuln_cols:
            db.session.execute(
                text('ALTER TABLE vulnerability ADD COLUMN zap_alert_id VARCHAR(50)'))
            db.session.commit()
            logger.info("Migrated: added vulnerability.zap_alert_id column")
    except Exception as e:
        logger.warning("Schema migration check failed: %s", e)


if __name__ == '__main__':
    print("Starting VulnScan Pro backend...")
    try:
        with app.app_context():
            db.create_all()
            ensure_user_schema()
            print("Database initialized.")
            if not User.query.filter_by(username='admin').first():
                admin = User(username='admin',
                             email='admin@vulnscanner.com', role='admin',
                             email_verified=True,
                             must_change_password=True)  # Force first-login password change
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                print("Admin user created (password change required on first login).")
            else:
                print("Admin user already exists.")

            # Seed realistic initial security logs if AuditLog table is empty
            if not AuditLog.query.first():
                db.session.add(AuditLog(event_type='user_created', username='admin', ip_address='127.0.0.1',
                               details='Primary administrator account initialized during database seeding.'))
                db.session.add(AuditLog(event_type='config_update', username='system', ip_address='127.0.0.1',
                               details='Loaded default security profiles: RL_MAX=14, LOCK_THRESHOLD=5.'))
                db.session.add(AuditLog(event_type='login_success', username='admin',
                               ip_address='127.0.0.1', details='Admin logged in successfully from localhost.'))
                db.session.commit()
            # Start background scheduler for scheduled scans
            sched_thread = threading.Thread(
                target=start_scheduled_scan_worker, args=(app, socketio))
            sched_thread.daemon = True
            sched_thread.start()
        port = int(os.environ.get('PORT', 5000))
        # Bind 127.0.0.1 by default (safe for local dev); containers set HOST=0.0.0.0.
        host = "0.0.0.0"
        print(f"Server running at http://{host}:{port}")
        print("Press Ctrl+C to stop.")
        socketio.run(app, host=host, port=port,
                     debug=True, use_reloader=False)
    except Exception as e:
        print(f"ERROR starting server: {e}")
        import traceback
        traceback.print_exc()
