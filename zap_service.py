"""
zap_service.py — VulnScan Pro ZAP Service Layer
================================================
This module is the ONLY component in VulnScan Pro that communicates
with OWASP ZAP.  Flask routes import this module and call its
functions.  The browser / JavaScript frontend NEVER talks to ZAP
directly — all ZAP traffic flows through this layer.

Communication path:
    Browser  →  Flask (backend_app.py)  →  zap_service.py
             →  Cloudflare Tunnel  →  OWASP ZAP  →  Target

Security contract:
    • ZAP_API_URL  — read from environment variable only; never exposed to clients
    • ZAP_API_KEY  — sent in X-ZAP-API-Key request HEADER only; never in URLs,
                     never logged, never returned in API responses
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Module logger — ZAP_API_KEY is NEVER passed to logger calls
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Timeout / polling constants — safe to read at module-load time
# ---------------------------------------------------------------------------
ZAP_CONNECT_TIMEOUT: int = int(os.environ.get('ZAP_CONNECT_TIMEOUT', '10'))
ZAP_REQUEST_TIMEOUT: int = int(os.environ.get('ZAP_REQUEST_TIMEOUT', '30'))
ZAP_SPIDER_TIMEOUT:  int = int(os.environ.get(
    'ZAP_SPIDER_TIMEOUT',  '600'))   # 10 min
ZAP_PSCAN_TIMEOUT:   int = int(os.environ.get(
    'ZAP_PSCAN_TIMEOUT',   '120'))  # 2 min
ZAP_ASCAN_TIMEOUT:   int = int(os.environ.get(
    'ZAP_ASCAN_TIMEOUT',   '3600'))  # 60 min
ZAP_POLL_INTERVAL:   int = int(os.environ.get(
    'ZAP_POLL_INTERVAL',   '5'))     # seconds


# ---------------------------------------------------------------------------
# Helper: read secrets lazily (at call time, not at import time)
# This ensures .env loading in backend_app.py has already run.
# ---------------------------------------------------------------------------

def _zap_api_url() -> str:
    """Return the configured ZAP API base URL (without trailing slash)."""
    return os.environ.get('ZAP_API_URL', '').rstrip('/')


def _zap_api_key() -> str:
    """Return the ZAP API key.  NEVER log or return this value to clients."""
    return os.environ.get('ZAP_API_KEY', '')


def is_configured() -> bool:
    """Return True if ZAP_API_URL has been set in the environment."""
    return bool(_zap_api_url())


# ---------------------------------------------------------------------------
# Custom Exception Hierarchy
# ---------------------------------------------------------------------------

class ZapError(Exception):
    """Base class for all ZAP service errors."""


class ZapUnavailableError(ZapError):
    """ZAP is not reachable — tunnel down, ZAP not running, wrong URL."""


class ZapAuthError(ZapError):
    """ZAP rejected the API key (HTTP 403)."""


class ZapScanError(ZapError):
    """ZAP returned an error during a scan operation."""


class ZapTimeoutError(ZapError):
    """A ZAP operation exceeded its configured timeout."""


class ZapNotConfiguredError(ZapError):
    """ZAP_API_URL environment variable is not set."""


# ---------------------------------------------------------------------------
# Private HTTP helper
# ---------------------------------------------------------------------------

def _make_session() -> requests.Session:
    """Build a requests.Session with conservative retry + backoff."""
    session = requests.Session()
    retry = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[502, 503, 504],
        allowed_methods=['GET', 'POST'],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def _zap_request(
    path: str,
    params: Optional[Dict[str, Any]] = None,
    method: str = 'GET',
    timeout: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Send a single authenticated request to the ZAP REST API.

    The API key is always placed in the  X-ZAP-API-Key  HEADER — it never
    appears in the URL, in query parameters, or in log messages.

    Args:
        path:    ZAP API path, e.g. '/JSON/core/view/version/'
        params:  Optional query/form parameters. Do NOT include 'apikey' here.
        method:  'GET' (default) or 'POST'
        timeout: Override default ZAP_REQUEST_TIMEOUT for this call.

    Returns:
        Parsed JSON response as a dict.

    Raises:
        ZapNotConfiguredError : ZAP_API_URL env var is not set.
        ZapUnavailableError   : Network / DNS / tunnel failure.
        ZapAuthError          : ZAP returned HTTP 403.
        ZapScanError          : ZAP returned a non-OK status or malformed JSON.
        ZapTimeoutError       : Request exceeded the timeout.
    """
    base = _zap_api_url()
    if not base:
        raise ZapNotConfiguredError(
            'ZAP_API_URL is not set. Configure it in your environment variables '
            'before using ZAP features.'
        )

    url = base + path
    # The API key travels in a header — never in the URL or query params.
    headers: Dict[str, str] = {'X-ZAP-API-Key': _zap_api_key()}
    _timeout = timeout if timeout is not None else ZAP_REQUEST_TIMEOUT

    session = _make_session()
    try:
        if method.upper() == 'POST':
            resp = session.post(url, params=params, headers=headers,
                                timeout=_timeout)
        else:
            resp = session.get(url, params=params, headers=headers,
                               timeout=_timeout)
    except requests.exceptions.ConnectionError as exc:
        raise ZapUnavailableError(
            'Cannot connect to ZAP. Verify that the Cloudflare tunnel is '
            'running and OWASP ZAP is listening on port 8080.'
        ) from exc
    except requests.exceptions.Timeout as exc:
        raise ZapTimeoutError(
            f'ZAP request timed out after {_timeout}s (path: {path})'
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise ZapUnavailableError(
            f'ZAP request failed ({type(exc).__name__}): {exc}'
        ) from exc
    finally:
        session.close()

    if resp.status_code == 403:
        raise ZapAuthError(
            'ZAP rejected the API key. Verify that ZAP_API_KEY matches the key '
            'set in OWASP ZAP → Tools → Options → API.'
        )
    if resp.status_code == 404:
        raise ZapScanError(f'ZAP endpoint not found: {path}')
    if not resp.ok:
        raise ZapScanError(
            f'ZAP returned HTTP {resp.status_code} for {path} '
            f'(response: {resp.text[:200]})'
        )

    try:
        return resp.json()
    except ValueError as exc:
        raise ZapScanError(
            f'ZAP returned non-JSON for {path}: {resp.text[:200]}'
        ) from exc


# ===========================================================================
# SECTION 1 — Availability & Status
# ===========================================================================

def check_zap_availability() -> Dict[str, Any]:
    """
    Perform a lightweight liveness check against ZAP.

    Returns:
        dict — {
            'reachable': bool,
            'version':   str | None,
            'message':   str,
        }
    """
    if not is_configured():
        return {
            'reachable': False,
            'version': None,
            'message': 'ZAP_API_URL environment variable is not configured.',
        }
    try:
        data = _zap_request('/JSON/core/view/version/',
                            timeout=ZAP_CONNECT_TIMEOUT)
        version = data.get('version', 'unknown')
        logger.info('[ZAP] Availability check passed — version %s', version)
        return {'reachable': True, 'version': version, 'message': 'ZAP is online.'}
    except ZapAuthError as exc:
        logger.warning('[ZAP] Reachable but API key rejected: %s', exc)
        return {
            'reachable': True,
            'version': None,
            'message': 'ZAP is reachable but the API key is invalid.',
        }
    except ZapError as exc:
        logger.warning('[ZAP] Availability check failed: %s', exc)
        return {'reachable': False, 'version': None, 'message': str(exc)}
    except Exception as exc:  # pragma: no cover
        logger.error(
            '[ZAP] Unexpected error during availability check: %s', exc)
        return {'reachable': False, 'version': None, 'message': str(exc)}


def get_zap_info() -> Dict[str, Any]:
    """
    Return detailed ZAP status: version, operating mode, and alerts-in-session.

    Returns:
        dict extending check_zap_availability() with 'mode' and
        'alerts_in_session' keys.
    """
    result = check_zap_availability()
    if not result.get('reachable'):
        return result

    try:
        mode_data = _zap_request('/JSON/core/view/mode/')
        result['mode'] = mode_data.get('mode', 'unknown')
    except ZapError:
        result['mode'] = 'unknown'

    try:
        alert_data = _zap_request('/JSON/core/view/numberOfAlerts/')
        result['alerts_in_session'] = int(alert_data.get('numberOfAlerts', 0))
    except (ZapError, ValueError):
        result['alerts_in_session'] = 0

    return result


# ===========================================================================
# SECTION 2 — Session Management
# ===========================================================================

def new_session(session_name: str = '') -> bool:
    """
    Create a fresh ZAP session, clearing all previous scan state.
    Should be called before each new scan to prevent stale results.

    Args:
        session_name: Optional human-readable name (e.g. first 8 chars of scan_id).

    Returns:
        True if the new session was created successfully.
    """
    params: Dict[str, str] = {'overwrite': 'true'}
    if session_name:
        params['name'] = session_name
    try:
        _zap_request('/JSON/core/action/newSession/',
                     params=params, method='POST')
        logger.info('[ZAP] New session created (name=%r)',
                    session_name or 'unnamed')
        return True
    except ZapError as exc:
        logger.warning('[ZAP] Failed to create new session: %s', exc)
        return False


def set_zap_mode(mode: str = 'standard') -> bool:
    """
    Set the ZAP operating mode.

    Args:
        mode: One of 'safe', 'standard', 'protected', or 'attack'.

    Returns:
        True if the mode was set successfully.
    """
    valid = {'safe', 'standard', 'protected', 'attack'}
    if mode not in valid:
        logger.warning('[ZAP] Invalid mode %r — defaulting to standard', mode)
        mode = 'standard'
    try:
        _zap_request('/JSON/core/action/setMode/',
                     params={'mode': mode}, method='POST')
        logger.info('[ZAP] Mode set to %r', mode)
        return True
    except ZapError as exc:
        logger.warning('[ZAP] Failed to set mode to %r: %s', mode, exc)
        return False


# ===========================================================================
# SECTION 3 — Spider Scan
# ===========================================================================

def start_spider(target_url: str, max_depth: int = 5) -> str:
    """
    Start a ZAP Spider scan against *target_url*.

    Args:
        target_url: The URL to spider (must be http or https).
        max_depth:  Maximum crawl depth (default 5).

    Returns:
        ZAP spider scan ID string (e.g. '0').

    Raises:
        ZapUnavailableError, ZapScanError
    """
    logger.info('[ZAP] Starting spider — target=%r depth=%d',
                target_url, max_depth)
    data = _zap_request('/JSON/spider/action/scan/', params={
        'url': target_url,
        'maxChildren': max_depth,
        'recurse': 'true',
    }, method='GET')
    scan_id = data.get('scan')
    if scan_id is None:
        raise ZapScanError(
            f'ZAP did not return a spider scan ID. Full response: {data}'
        )
    logger.info('[ZAP] Spider started — scan_id=%s', scan_id)
    return str(scan_id)


def get_spider_status(spider_id: str) -> int:
    """
    Return spider progress as an integer 0–100.
    """
    data = _zap_request('/JSON/spider/view/status/',
                        params={'scanId': spider_id})
    try:
        return int(data.get('status', 0))
    except (ValueError, TypeError):
        return 0


def get_spider_results(spider_id: str) -> List[str]:
    """
    Return the list of URLs discovered by the spider.
    """
    data = _zap_request('/JSON/spider/view/results/',
                        params={'scanId': spider_id})
    return data.get('results', [])


def wait_for_spider(
    spider_id: str,
    progress_callback: Optional[Callable[[int, str], None]] = None,
    cancelled_check: Optional[Callable[[], bool]] = None,
    timeout: Optional[int] = None,
) -> List[str]:
    """
    Poll until the spider reaches 100 % or the timeout is exceeded.

    This function is designed to run inside a background thread.

    Args:
        spider_id:         ZAP spider scan ID.
        progress_callback: Optional ``fn(progress: int, message: str)`` called
                           on each poll cycle for live Socket.IO updates.
        cancelled_check:   Optional ``fn() -> bool``; returns True if the scan
                           has been cancelled — causes early exit.
        timeout:           Override ZAP_SPIDER_TIMEOUT.

    Returns:
        List of URLs discovered.

    Raises:
        ZapTimeoutError: Spider did not finish within *timeout* seconds.
    """
    _timeout = timeout if timeout is not None else ZAP_SPIDER_TIMEOUT
    deadline = time.monotonic() + _timeout
    logger.info('[ZAP] Waiting for spider %s (timeout=%ds)',
                spider_id, _timeout)

    while True:
        if cancelled_check and cancelled_check():
            logger.info(
                '[ZAP] Spider wait cancelled by user (spider_id=%s)', spider_id)
            return []

        if time.monotonic() > deadline:
            raise ZapTimeoutError(
                f'ZAP spider (id={spider_id}) timed out after {_timeout}s.'
            )

        progress = get_spider_status(spider_id)
        logger.debug('[ZAP] Spider progress: %d%%', progress)

        if progress_callback:
            progress_callback(progress, f'Spider crawling… {progress}%')

        if progress >= 100:
            urls = get_spider_results(spider_id)
            logger.info('[ZAP] Spider complete — %d URL(s) found', len(urls))
            return urls

        time.sleep(ZAP_POLL_INTERVAL)


# ===========================================================================
# SECTION 4 — Passive Scan
# ===========================================================================

def get_passive_scan_queue() -> int:
    """
    Return the number of records still waiting for passive scan processing.
    A result of 0 means the passive scan is complete.
    """
    data = _zap_request('/JSON/pscan/view/recordsToScan/')
    try:
        return int(data.get('recordsToScan', 0))
    except (ValueError, TypeError):
        return 0


def wait_for_passive_scan(
    progress_callback: Optional[Callable[[int, str], None]] = None,
    cancelled_check: Optional[Callable[[], bool]] = None,
    timeout: Optional[int] = None,
) -> None:
    """
    Wait for the passive scan queue to drain to zero.

    ZAP automatically queues all traffic observed by the spider/proxy for
    passive analysis.  This function waits for that queue to empty.

    A timeout is non-fatal — execution proceeds with whatever passive results
    exist (better partial results than a hard failure).

    Args:
        progress_callback: Optional ``fn(progress: int, message: str)``.
        cancelled_check:   Optional ``fn() -> bool``.
        timeout:           Override ZAP_PSCAN_TIMEOUT.
    """
    _timeout = timeout if timeout is not None else ZAP_PSCAN_TIMEOUT
    deadline = time.monotonic() + _timeout
    logger.info('[ZAP] Waiting for passive scan (timeout=%ds)', _timeout)

    while True:
        if cancelled_check and cancelled_check():
            logger.info('[ZAP] Passive scan wait cancelled by user')
            return

        if time.monotonic() > deadline:
            logger.warning(
                '[ZAP] Passive scan wait timed out — proceeding anyway')
            return  # Non-fatal: proceed with whatever passive results exist

        remaining = get_passive_scan_queue()
        logger.debug(
            '[ZAP] Passive scan queue: %d record(s) remaining', remaining)

        if progress_callback:
            progress_callback(
                0, f'Passive scan processing… {remaining} record(s) remaining'
            )

        if remaining == 0:
            logger.info('[ZAP] Passive scan complete')
            return

        time.sleep(ZAP_POLL_INTERVAL)


# ===========================================================================
# SECTION 5 — Active Scan
# ===========================================================================

def start_active_scan(target_url: str, scan_policy: str = '') -> str:
    """
    Start a ZAP Active (attack) Scan against *target_url*.

    Args:
        target_url:  URL to actively scan.
        scan_policy: Optional ZAP scan-policy name (empty = ZAP default).

    Returns:
        ZAP active scan ID string.

    Raises:
        ZapUnavailableError, ZapScanError
    """
    params: Dict[str, str] = {'url': target_url, 'recurse': 'true'}
    if scan_policy:
        params['scanPolicyName'] = scan_policy
    logger.info('[ZAP] Starting active scan — target=%r', target_url)
    data = _zap_request('/JSON/ascan/action/scan/',
                        params=params, method='GET')
    scan_id = data.get('scan')
    if scan_id is None:
        raise ZapScanError(
            f'ZAP did not return an active scan ID. Full response: {data}'
        )
    logger.info('[ZAP] Active scan started — scan_id=%s', scan_id)
    return str(scan_id)


def get_active_scan_status(ascan_id: str) -> int:
    """
    Return active scan progress as an integer 0–100.
    """
    data = _zap_request('/JSON/ascan/view/status/',
                        params={'scanId': ascan_id})
    try:
        return int(data.get('status', 0))
    except (ValueError, TypeError):
        return 0


def stop_active_scan(ascan_id: str) -> bool:
    """
    Request ZAP to stop a running active scan immediately.

    Returns:
        True if ZAP acknowledged the stop request.
    """
    try:
        _zap_request('/JSON/ascan/action/stop/',
                     params={'scanId': ascan_id}, method='POST')
        logger.info('[ZAP] Active scan stop sent — ascan_id=%s', ascan_id)
        return True
    except ZapError as exc:
        logger.warning(
            '[ZAP] Could not stop active scan %s: %s', ascan_id, exc)
        return False


def wait_for_active_scan(
    ascan_id: str,
    progress_callback: Optional[Callable[[int, str], None]] = None,
    cancelled_check: Optional[Callable[[], bool]] = None,
    timeout: Optional[int] = None,
) -> None:
    """
    Poll until the active scan reaches 100 % or the timeout is exceeded.

    If the timeout is reached the scan is stopped in ZAP and a
    ZapTimeoutError is raised so the caller can mark the scan as 'failed'.

    Args:
        ascan_id:          ZAP active scan ID.
        progress_callback: Optional ``fn(progress: int, message: str)``.
        cancelled_check:   Optional ``fn() -> bool``.
        timeout:           Override ZAP_ASCAN_TIMEOUT.

    Raises:
        ZapTimeoutError: Scan did not finish within *timeout* seconds.
    """
    _timeout = timeout if timeout is not None else ZAP_ASCAN_TIMEOUT
    deadline = time.monotonic() + _timeout
    logger.info('[ZAP] Waiting for active scan %s (timeout=%ds)',
                ascan_id, _timeout)

    while True:
        if cancelled_check and cancelled_check():
            stop_active_scan(ascan_id)
            logger.info(
                '[ZAP] Active scan cancelled by user — ascan_id=%s', ascan_id)
            return

        if time.monotonic() > deadline:
            stop_active_scan(ascan_id)
            raise ZapTimeoutError(
                f'ZAP active scan (id={ascan_id}) timed out after {_timeout}s. '
                f'Scan has been stopped.'
            )

        progress = get_active_scan_status(ascan_id)
        logger.debug('[ZAP] Active scan progress: %d%%', progress)

        if progress_callback:
            progress_callback(
                progress, f'Active scan in progress… {progress}%')

        if progress >= 100:
            logger.info('[ZAP] Active scan complete — ascan_id=%s', ascan_id)
            return

        time.sleep(ZAP_POLL_INTERVAL)


# ===========================================================================
# SECTION 6 — Ajax Spider (for JavaScript-heavy SPAs)
# ===========================================================================

def start_ajax_spider(target_url: str) -> bool:
    """
    Start ZAP's Ajax Spider for JavaScript-rendered single-page applications.

    Returns:
        True if the spider was started successfully.
    """
    logger.info('[ZAP] Starting Ajax Spider — target=%r', target_url)
    try:
        _zap_request('/JSON/ajaxSpider/action/scan/',
                     params={'url': target_url}, method='POST')
        return True
    except ZapError as exc:
        logger.warning('[ZAP] Ajax Spider start failed: %s', exc)
        return False


def get_ajax_spider_status() -> str:
    """
    Return the Ajax Spider status string: 'running' or 'stopped'.
    """
    try:
        data = _zap_request('/JSON/ajaxSpider/view/status/')
        return data.get('status', 'stopped')
    except ZapError:
        return 'stopped'


def stop_ajax_spider() -> bool:
    """Stop the Ajax Spider if it is running."""
    try:
        _zap_request('/JSON/ajaxSpider/action/stop/', method='POST')
        logger.info('[ZAP] Ajax Spider stop requested')
        return True
    except ZapError as exc:
        logger.warning('[ZAP] Ajax Spider stop failed: %s', exc)
        return False


# ===========================================================================
# SECTION 7 — Alerts & Results
# ===========================================================================

# ZAP riskcode → VulnScanPro severity
_RISK_CODE_TO_SEVERITY: Dict[str, str] = {
    '3': 'critical',
    '2': 'high',
    '1': 'medium',
    '0': 'low',
}

# ZAP risk string → VulnScanPro severity (fallback when riskcode is absent)
_RISK_NAME_TO_SEVERITY: Dict[str, str] = {
    'High':          'high',
    'Medium':        'medium',
    'Low':           'low',
    'Informational': 'info',
}

# Approximate CVSS base scores for severity bands (ZAP does not provide CVSS)
_SEVERITY_TO_CVSS: Dict[str, float] = {
    'critical': 9.1,
    'high':     7.5,
    'medium':   5.3,
    'low':      3.1,
    'info':     0.0,
}


def _resolve_severity(alert: Dict[str, Any]) -> str:
    """Resolve a ZAP alert dict to a VulnScanPro severity string."""
    riskcode = str(alert.get('riskcode', '-1'))
    risk_name = alert.get('risk', '')
    return (
        _RISK_CODE_TO_SEVERITY.get(riskcode)
        or _RISK_NAME_TO_SEVERITY.get(risk_name, 'info')
    )


def _normalize_vuln_type(alert_name: str) -> str:
    """Map a ZAP alert name to a normalised vuln_type slug."""
    n = alert_name.lower()
    if 'sql' in n:
        return 'sql_injection'
    if 'xss' in n or 'cross-site script' in n:
        return 'xss'
    if 'csrf' in n:
        return 'csrf'
    if 'ssrf' in n:
        return 'ssrf'
    if 'path traversal' in n or 'directory' in n:
        return 'path_traversal'
    if 'ssl' in n or 'tls' in n or 'https' in n:
        return 'sensitive_data_exposure'
    if 'redirect' in n or 'open redirect' in n:
        return 'broken_access_control'
    if 'cors' in n:
        return 'security_misconfiguration'
    if 'injection' in n:
        return 'injection'
    if 'header' in n:
        return 'security_misconfiguration'
    if 'information' in n or 'disclosure' in n:
        return 'information_disclosure'
    return 'security_misconfiguration'


def get_alerts(
    base_url: Optional[str] = None,
    risk_level: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Fetch all alerts from ZAP's current session.

    Args:
        base_url:   If set, only return alerts whose URL starts with this value.
        risk_level: Optional filter: 'High', 'Medium', 'Low', 'Informational'.

    Returns:
        List of raw ZAP alert dicts.

    Raises:
        ZapError subclasses on connectivity or auth failure.
    """
    params: Dict[str, str] = {}
    if base_url:
        params['baseurl'] = base_url
    if risk_level:
        risk_id_map = {'High': '3', 'Medium': '2',
                       'Low': '1', 'Informational': '0'}
        rid = risk_id_map.get(risk_level)
        if rid:
            params['riskId'] = rid

    data = _zap_request('/JSON/core/view/alerts/', params=params)
    alerts = data.get('alerts', [])
    logger.info('[ZAP] Retrieved %d alert(s) (base_url=%r)',
                len(alerts), base_url)
    return alerts


def map_alert_to_vulnerability(
    alert: Dict[str, Any],
    scan_id: str,
) -> Dict[str, Any]:
    """
    Map a raw ZAP alert dict to the VulnScanPro Vulnerability model format.

    Args:
        alert:   Raw ZAP alert dict from get_alerts().
        scan_id: VulnScanPro Scan UUID to associate the vulnerability with.

    Returns:
        Dict whose keys correspond to Vulnerability model columns.
        Also includes 'zap_alert_id' (plugin ID) for deduplication.
    """
    severity = _resolve_severity(alert)

    cwe_raw = str(alert.get('cweid', '-1'))
    cwe_id = f'CWE-{cwe_raw}' if cwe_raw not in ('-1', '', 'None') else None

    plugin_id = str(
        alert.get('pluginId', alert.get('pluginid', ''))
    )

    return {
        'scan_id':       scan_id,
        'vuln_type':     _normalize_vuln_type(alert.get('alert', 'unknown')),
        'severity':      severity,
        'title':         alert.get('alert', 'Unknown Alert'),
        'description':   alert.get('description', 'No description provided by ZAP.'),
        'affected_url':  alert.get('url', ''),
        'parameter':     alert.get('param', ''),
        'payload':       alert.get('attack', ''),
        'evidence':      alert.get('evidence', ''),
        'remediation':   alert.get('solution', ''),
        'cvss_score':    _SEVERITY_TO_CVSS.get(severity, 0.0),
        'cwe_id':        cwe_id,
        # Stored on the Vulnerability row for deduplication; not a foreign key.
        'zap_alert_id':  plugin_id,
    }


def get_risk_summary(base_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Compute a severity-breakdown risk summary from ZAP alerts.

    Returns:
        dict — {
            'critical': int, 'high': int, 'medium': int,
            'low': int, 'info': int, 'total': int,
            'risk_score': int   # 0–100 weighted score
        }
    """
    empty: Dict[str, Any] = {
        'critical': 0, 'high': 0, 'medium': 0,
        'low': 0, 'info': 0, 'total': 0, 'risk_score': 0,
    }
    try:
        alerts = get_alerts(base_url=base_url)
    except ZapError as exc:
        logger.warning('[ZAP] Cannot compute risk summary: %s', exc)
        return empty

    counts: Dict[str, int] = {
        'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
    }
    for alert in alerts:
        sev = _resolve_severity(alert)
        counts[sev] = counts.get(sev, 0) + 1

    total = sum(counts.values())
    # Weighted risk score (capped at 100)
    score = min(100, (
        counts['critical'] * 25 +
        counts['high'] * 15 +
        counts['medium'] * 8 +
        counts['low'] * 3 +
        counts['info'] * 1
    ))
    return {**counts, 'total': total, 'risk_score': score}


# ===========================================================================
# SECTION 8 — URL Validation
# ===========================================================================

def validate_scan_target(url: str) -> tuple[bool, str]:
    """
    Validate a user-supplied scan target URL before sending it to ZAP.

    Checks performed:
        1. Non-empty string
        2. Parseable URL (has scheme and netloc)
        3. Scheme is http or https only
        4. Not obviously pointing at the Flask application itself

    NOTE: Private / RFC-1918 IP ranges are intentionally allowed because
    pentesters legitimately need to scan internal targets through ZAP.

    Args:
        url: URL string supplied by the API consumer.

    Returns:
        (True, '') if valid; (False, '<reason>') if invalid.
    """
    if not url or not url.strip():
        return False, 'Target URL must not be empty.'

    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
    except Exception:
        return False, 'Target URL could not be parsed.'

    if parsed.scheme not in ('http', 'https'):
        return False, 'Target URL must use http or https scheme.'

    if not parsed.netloc:
        return False, 'Target URL must include a valid hostname.'

    return True, ''
