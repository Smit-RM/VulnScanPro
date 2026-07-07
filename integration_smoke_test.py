import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
"""
Security Feature Test Suite
============================
Tests both features against a running VulnScan Pro server:
  1. Server-side input validation & sanitization
  2. Rate limiting & account lockout

Usage:
    1. Start the server:   python backend_app.py
    2. Run this script:    python test_security_features.py

The script creates a temporary test user, runs all tests, then prints a summary.
"""

import requests
import time
import json
import sys
import uuid

BASE_URL = "http://127.0.0.1:5000"
REGISTER_URL = f"{BASE_URL}/api/auth/register"
LOGIN_URL = f"{BASE_URL}/api/auth/login"

# Unique test user (avoids collisions on re-runs)
_suffix = uuid.uuid4().hex[:6]
TEST_USER = f"testuser{_suffix}"
TEST_EMAIL = f"test{_suffix}@example.com"
TEST_PASSWORD = "SecurePass123"

passed = 0
failed = 0
results = []


def header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        status = "PASS"
        mark = "[PASS]"
    else:
        failed += 1
        status = "FAIL"
        mark = "[FAIL]"
    results.append((status, name))
    line = f"  {mark} {name}"
    if detail:
        line += f"  ({detail})"
    print(line)


def safe_post(url, json_data=None, raw_data=None, timeout=15):
    """POST with error handling."""
    try:
        if raw_data is not None:
            return requests.post(url, data=raw_data,
                                 headers={"Content-Type": "application/json"},
                                 timeout=timeout)
        return requests.post(url, json=json_data, timeout=timeout)
    except requests.exceptions.ConnectionError:
        print(f"\n  ERROR: Cannot connect to {BASE_URL}")
        print(f"  Make sure the server is running: python backend_app.py\n")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────
# Pre-flight: create a test user
# ──────────────────────────────────────────────────────────────

print(f"\nConnecting to {BASE_URL} ...")
resp = safe_post(REGISTER_URL, {
    "username": TEST_USER,
    "email": TEST_EMAIL,
    "password": TEST_PASSWORD,
    "display_name": "Test User"
})
if resp.status_code == 201:
    print(f"  Created test user: {TEST_USER}")
    from itsdangerous import URLSafeTimedSerializer
    import os
    sec_key = os.environ.get("SECRET_KEY", "vuln-scanner-secret-key-2024")
    serializer = URLSafeTimedSerializer(sec_key, salt="email-verify")
    token = serializer.dumps({"uid": resp.json().get("user", {}).get("id")})
    requests.get(f"{BASE_URL}/api/auth/verify-email?token={token}")
elif resp.status_code == 409:
    print(f"  Test user already exists: {TEST_USER}")
else:
    print(f"  WARNING: Unexpected register response: {resp.status_code} {resp.text[:200]}")


# ══════════════════════════════════════════════════════════════
# FEATURE 1: INPUT VALIDATION & SANITIZATION
# ══════════════════════════════════════════════════════════════

header("FEATURE 1: Input Validation & Sanitization")

# ── 1a. Registration validation ──────────────────────────────

print("\n  --- Registration Validation ---")

# Empty body
resp = safe_post(REGISTER_URL, {})
check("Register: empty body → 400",
      resp.status_code == 400,
      f"status={resp.status_code}")

# Missing fields
resp = safe_post(REGISTER_URL, {"username": "onlyuser"})
check("Register: missing email/password → 400",
      resp.status_code == 400,
      f"status={resp.status_code}")

# Username too short
resp = safe_post(REGISTER_URL, {
    "username": "ab", "email": "x@y.com", "password": "ValidPass1"
})
check("Register: username too short (2 chars) → 400",
      resp.status_code == 400,
      f"status={resp.status_code}")

# Username with special chars
resp = safe_post(REGISTER_URL, {
    "username": "<script>alert(1)</script>",
    "email": "xss@test.com",
    "password": "ValidPass1"
})
check("Register: XSS in username → 400",
      resp.status_code == 400,
      f"status={resp.status_code}")

# Invalid email format
resp = safe_post(REGISTER_URL, {
    "username": "validuser01", "email": "not-an-email", "password": "ValidPass1"
})
check("Register: invalid email format → 400",
      resp.status_code == 400,
      f"status={resp.status_code}")

# Password too short
resp = safe_post(REGISTER_URL, {
    "username": "validuser02", "email": "v2@test.com", "password": "Ab1"
})
check("Register: password too short → 400",
      resp.status_code == 400,
      f"status={resp.status_code}")

# Password without digits
resp = safe_post(REGISTER_URL, {
    "username": "validuser03", "email": "v3@test.com", "password": "NoDigitsHere"
})
check("Register: password no digits → 400",
      resp.status_code == 400,
      f"status={resp.status_code}")

# HTML in display name gets sanitized
resp = safe_post(REGISTER_URL, {
    "username": "validuser04", "email": "v4@test.com",
    "password": "ValidPass1",
    "display_name": "<b>Bold</b> Name"
})
# After sanitization the display name becomes "Bold Name" which is valid,
# so it should succeed (or 409 if user exists from a prior run)
check("Register: HTML in display_name → sanitized (not 400 for valid result)",
      resp.status_code in (201, 409),
      f"status={resp.status_code}")

# Specific error message (shows field-specific info as requested)
resp = safe_post(REGISTER_URL, {
    "username": "ab", "email": "bad", "password": "x"
})
body = resp.json()
error_msg = body.get("error", "")
has_field_info = any(word in error_msg.lower()
                     for word in ["username", "email", "password"])
check("Register: error message is specific (contains field validation errors)",
      resp.status_code == 400 and has_field_info,
      f'msg="{error_msg[:80]}"')

# Non-JSON body
resp = safe_post(REGISTER_URL, raw_data="this is not json")
check("Register: non-JSON body → 400",
      resp.status_code == 400,
      f"status={resp.status_code}")

# ── 1b. Login validation ─────────────────────────────────────

print("\n  --- Login Validation ---")

# Empty body
resp = safe_post(LOGIN_URL, {})
check("Login: empty body → 401",
      resp.status_code == 401,
      f"status={resp.status_code}")

# Username with HTML injection
resp = safe_post(LOGIN_URL, {
    "username": '<img src=x onerror="alert(1)">',
    "password": "anything"
})
check("Login: XSS in username → 401 (rejected)",
      resp.status_code == 401,
      f"status={resp.status_code}")

# Non-JSON body
resp = safe_post(LOGIN_URL, raw_data="not json at all")
check("Login: non-JSON body → 401",
      resp.status_code == 401,
      f"status={resp.status_code}")

# Valid credentials still work
resp = safe_post(LOGIN_URL, {
    "username": TEST_USER, "password": TEST_PASSWORD
})
normal_token = ""
if resp.status_code == 200:
    normal_token = resp.json().get("token", "")
check("Login: valid credentials → 200 + token",
      resp.status_code == 200 and normal_token != "",
      f"status={resp.status_code}")


# ══════════════════════════════════════════════════════════════
# FEATURE 2: Rate Limiting & Account Lockout
# ══════════════════════════════════════════════════════════════

header("FEATURE 2: Rate Limiting & Account Lockout")

# Use a dedicated user for lockout tests
_lock_suffix = uuid.uuid4().hex[:6]
LOCK_USER = f"locktest{_lock_suffix}"
LOCK_EMAIL = f"lock{_lock_suffix}@example.com"
LOCK_PASSWORD = "LockTestPass1"

resp = safe_post(REGISTER_URL, {
    "username": LOCK_USER, "email": LOCK_EMAIL,
    "password": LOCK_PASSWORD
})
if resp.status_code in (201, 409):
    print(f"\n  Lockout test user: {LOCK_USER}")
    if resp.status_code == 201:
        from itsdangerous import URLSafeTimedSerializer
        import os
        sec_key = os.environ.get("SECRET_KEY", "vuln-scanner-secret-key-2024")
        serializer = URLSafeTimedSerializer(sec_key, salt="email-verify")
        token = serializer.dumps({"uid": resp.json().get("user", {}).get("id")})
        requests.get(f"{BASE_URL}/api/auth/verify-email?token={token}")

# ── 2a. Progressive delay ────────────────────────────────────

print("\n  --- Progressive Delay ---")

timings = []
for i in range(4):
    start = time.time()
    resp = safe_post(LOGIN_URL, {
        "username": LOCK_USER, "password": "WrongPassword1"
    })
    elapsed = time.time() - start
    timings.append(elapsed)
    print(f"    Attempt {i+1}: {elapsed:.2f}s  (status={resp.status_code})")

check("Progressive delay: attempt 3 slower than attempt 1",
      len(timings) >= 3 and timings[2] > timings[0],
      f"t1={timings[0]:.2f}s t3={timings[2]:.2f}s")

# ── 2b. Account lockout after 5 fails ────────────────────────

print("\n  --- Account Lockout (5 consecutive fails) ---")

# We already have 4 failures above, send one more to trigger lockout
resp = safe_post(LOGIN_URL, {
    "username": LOCK_USER, "password": "WrongPassword1"
})
print(f"    Attempt 5 (trigger lock): status={resp.status_code}")

# Now try the CORRECT password — should still be rejected (account locked)
resp = safe_post(LOGIN_URL, {
    "username": LOCK_USER, "password": LOCK_PASSWORD
})
check("Lockout: correct password rejected while locked → 401",
      resp.status_code == 401,
      f"status={resp.status_code}")

# ── 2c. Indistinguishable responses ──────────────────────────

print("\n  --- Indistinguishable Responses ---")

# Wrong password on a normal user
resp_wrong = safe_post(LOGIN_URL, {
    "username": TEST_USER, "password": "TotallyWrong1"
})

# Correct password on a locked user
resp_locked = safe_post(LOGIN_URL, {
    "username": LOCK_USER, "password": LOCK_PASSWORD
})

# Non-existent user
resp_nouser = safe_post(LOGIN_URL, {
    "username": "nonexistentuser999", "password": "Whatever1"
})

wrong_body = resp_wrong.json().get("error", "")
locked_body = resp_locked.json().get("error", "")
nouser_body = resp_nouser.json().get("error", "")

check("Same status code: wrong-pw / locked / no-user",
      resp_wrong.status_code == resp_locked.status_code == resp_nouser.status_code == 401,
      f"codes: {resp_wrong.status_code}/{resp_locked.status_code}/{resp_nouser.status_code}")

check("Same error message: wrong-pw / locked / no-user",
      wrong_body == locked_body == nouser_body,
      f'msgs: "{wrong_body}" / "{locked_body}" / "{nouser_body}"')

no_lockout_hint = not any(
    word in locked_body.lower()
    for word in ["locked", "too many", "attempts", "blocked", "lockout"]
)
check("Error message doesn't reveal lockout",
      no_lockout_hint,
      f'msg="{locked_body}"')


# ══════════════════════════════════════════════════════════════
# FEATURE 3: ADMIN PANEL SECURITY
# ══════════════════════════════════════════════════════════════

header("FEATURE 3: Admin Panel Security")

# Re-use normal user token obtained during valid credentials test
check("Login as normal user succeeded (re-used)", normal_token != "")

normal_headers = {"Authorization": f"Bearer {normal_token}"}

# 2. Assert normal user is blocked from admin routes (403 Forbidden)
r_users = requests.get(f"{BASE_URL}/api/admin/users", headers=normal_headers)
check("Normal user blocked from /api/admin/users", r_users.status_code == 403, f"code: {r_users.status_code}")

r_logs = requests.get(f"{BASE_URL}/api/admin/logs", headers=normal_headers)
check("Normal user blocked from /api/admin/logs", r_logs.status_code == 403, f"code: {r_logs.status_code}")

r_config = requests.get(f"{BASE_URL}/api/admin/config", headers=normal_headers)
check("Normal user blocked from /api/admin/config", r_config.status_code == 403, f"code: {r_config.status_code}")

# 3. Login as admin user and get token
admin_login_resp = safe_post(LOGIN_URL, {
    "username": "admin",
    "password": "admin123"
})
admin_token = ""
if admin_login_resp.status_code == 200:
    admin_token = admin_login_resp.json().get("token", "")

check("Login as admin user succeeded", admin_login_resp.status_code == 200, f"code: {admin_login_resp.status_code}")

admin_headers = {"Authorization": f"Bearer {admin_token}"}

# 4. Assert admin user is authorized for admin routes (200 OK)
r_admin_users = requests.get(f"{BASE_URL}/api/admin/users", headers=admin_headers)
check("Admin authorized for /api/admin/users", r_admin_users.status_code == 200, f"code: {r_admin_users.status_code}")

r_admin_logs = requests.get(f"{BASE_URL}/api/admin/logs", headers=admin_headers)
check("Admin authorized for /api/admin/logs", r_admin_logs.status_code == 200, f"code: {r_admin_logs.status_code}")

r_admin_config = requests.get(f"{BASE_URL}/api/admin/config", headers=admin_headers)
check("Admin authorized for /api/admin/config", r_admin_config.status_code == 200, f"code: {r_admin_config.status_code}")

# 5. Test fetching user info and role update as admin
if r_admin_users.status_code == 200:
    users_list = r_admin_users.json()
    test_user_obj = next((u for u in users_list if u["username"] == TEST_USER), None)
    if test_user_obj:
        u_id = test_user_obj["id"]
        # Update user's role to admin
        r_update = requests.put(f"{BASE_URL}/api/admin/users/{u_id}", headers=admin_headers, json={"role": "admin"})
        check("Admin can update user role", r_update.status_code == 200, f"code: {r_update.status_code}")
        
        # Verify the role updated
        if r_update.status_code == 200:
            check("Role was successfully changed to admin", r_update.json().get("role") == "admin")
            # Revert user's role to user
            requests.put(f"{BASE_URL}/api/admin/users/{u_id}", headers=admin_headers, json={"role": "user"})
            
            # Test user deactivation (disable)
            r_deactivate = requests.put(f"{BASE_URL}/api/admin/users/{u_id}", headers=admin_headers, json={"is_active": False})
            check("Admin can deactivate user", r_deactivate.status_code == 200, f"code: {r_deactivate.status_code}")
            if r_deactivate.status_code == 200:
                check("User is_active was set to False", r_deactivate.json().get("is_active") == False)
                
                # Temporarily raise rate limit to avoid 429 during deactivated login test
                requests.put(f"{BASE_URL}/api/admin/config", headers=admin_headers, json={"LOGIN_RL_MAX": 100})

                # Assert disabled user cannot log in
                r_disabled_login = safe_post(LOGIN_URL, {"username": TEST_USER, "password": TEST_PASSWORD})
                check("Disabled user login rejected (403)", r_disabled_login.status_code == 403, f"code: {r_disabled_login.status_code}")
                if r_disabled_login.status_code == 403:
                    check("Disabled login response contains error", "temporarily disabled" in r_disabled_login.json().get("error", "").lower())
                
                # Restore rate limit
                requests.put(f"{BASE_URL}/api/admin/config", headers=admin_headers, json={"LOGIN_RL_MAX": 10})
                    
                # Re-activate user
                r_activate = requests.put(f"{BASE_URL}/api/admin/users/{u_id}", headers=admin_headers, json={"is_active": True})
                check("Admin can re-activate user", r_activate.status_code == 200, f"code: {r_activate.status_code}")
                
                # 7. Test Email Verification
                print("\n  --- Email Verification Flow ---")
                verify_suffix = uuid.uuid4().hex[:6]
                VERIFY_USER = f"verifyuser{verify_suffix}"
                VERIFY_EMAIL = f"verify{verify_suffix}@example.com"
                VERIFY_PW = "VerifyPass123"
                
                # Temporarily bump rate limit
                requests.put(f"{BASE_URL}/api/admin/config", headers=admin_headers, json={"LOGIN_RL_MAX": 100})
                
                r_reg = safe_post(REGISTER_URL, {
                    "username": VERIFY_USER, "email": VERIFY_EMAIL, "password": VERIFY_PW
                })
                check("Register verify user succeeded", r_reg.status_code == 201)
                
                if r_reg.status_code == 201:
                    v_user_id = r_reg.json().get("user", {}).get("id")
                    
                    # Try logging in before verifying email
                    r_unverified_login = safe_post(LOGIN_URL, {"username": VERIFY_USER, "password": VERIFY_PW})
                    check("Unverified user login rejected (403)", r_unverified_login.status_code == 403, f"code: {r_unverified_login.status_code}")
                    if r_unverified_login.status_code == 403:
                        check("Unverified login response contains verify message", "verify your email" in r_unverified_login.json().get("error", "").lower())
                    
                    # Verify with invalid token
                    r_invalid_verify = requests.get(f"{BASE_URL}/api/auth/verify-email?token=invalidtoken123")
                    check("Verify with invalid token rejected (400)", r_invalid_verify.status_code == 400)
                    
                    # Generate a valid verification token using itsdangerous
                    from itsdangerous import URLSafeTimedSerializer
                    import os
                    sec_key = os.environ.get("SECRET_KEY", "vuln-scanner-secret-key-2024")
                    serializer = URLSafeTimedSerializer(sec_key, salt="email-verify")
                    valid_token = serializer.dumps({"uid": v_user_id})
                    
                    # Verify with valid token
                    r_valid_verify = requests.get(f"{BASE_URL}/api/auth/verify-email?token={valid_token}", allow_redirects=False)
                    check("Verify with valid token accepts (302/200)", r_valid_verify.status_code in (200, 302))
                    
                    # Try logging in after verifying email
                    r_verified_login = safe_post(LOGIN_URL, {"username": VERIFY_USER, "password": VERIFY_PW})
                    check("Verified user login accepted (200)", r_verified_login.status_code == 200)
                
                # Restore rate limit
                requests.put(f"{BASE_URL}/api/admin/config", headers=admin_headers, json={"LOGIN_RL_MAX": 10})
    else:
        check("Admin can update user role", False, f"Test user {TEST_USER} not found in users list")
else:
    check("Admin can update user role", False, "Failed to get users list")

# 6. Test updating configurations
r_normal_cfg = requests.put(f"{BASE_URL}/api/admin/config", headers=normal_headers, json={"LOGIN_RL_MAX": 20})
check("Normal user forbidden from updating config", r_normal_cfg.status_code == 403, f"code: {r_normal_cfg.status_code}")

if r_admin_config.status_code == 200:
    orig_max = r_admin_config.json().get("LOGIN_RL_MAX", 14)
    r_admin_cfg_put = requests.put(f"{BASE_URL}/api/admin/config", headers=admin_headers, json={"LOGIN_RL_MAX": 22})
    check("Admin can update config cap", r_admin_cfg_put.status_code == 200, f"code: {r_admin_cfg_put.status_code}")
    if r_admin_cfg_put.status_code == 200:
        check("Config cap actually changed in response", r_admin_cfg_put.json().get("LOGIN_RL_MAX") == 22)
        r_admin_cfg_get = requests.get(f"{BASE_URL}/api/admin/config", headers=admin_headers)
        check("Config cap changed on subsequent GET", r_admin_cfg_get.json().get("LOGIN_RL_MAX") == 22)
        # Restore original value
        requests.put(f"{BASE_URL}/api/admin/config", headers=admin_headers, json={"LOGIN_RL_MAX": orig_max})
else:
    check("Admin can update config cap", False, "Failed to get original config")


# ── 2d. Rate limiting (10/IP/min) ────────────────────────────

print("\n  --- IP Rate Limiting (10 req/min) ---")
print("    Sending rapid login requests...")

rate_limit_hit = False
statuses = []
# We've already used several requests above; send more to exhaust the limit
for i in range(12):
    resp = safe_post(LOGIN_URL, {
        "username": "ratelimitprobe", "password": "whatever"
    })
    statuses.append(resp.status_code)
    if resp.status_code == 429:
        rate_limit_hit = True
        print(f"    → 429 received on request #{i+1}")
        retry = resp.headers.get("Retry-After", "?")
        check("Rate limit: 429 includes Retry-After header",
              retry != "?",
              f"Retry-After={retry}")
        break

check("Rate limit: 429 triggered within burst",
      rate_limit_hit,
      f"statuses={statuses}")


# ══════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════

header("TEST SUMMARY")
print(f"\n  Total:  {passed + failed}")
print(f"  Passed: {passed}")
print(f"  Failed: {failed}")
print()

for status, name in results:
    mark = "[PASS]" if status == "PASS" else "[FAIL]"
    print(f"  {mark} [{status}] {name}")

print()
if failed == 0:
    print("  All tests passed! Both security features are working correctly.")
else:
    print(f"  {failed} test(s) failed — review output above for details.")
print()

sys.exit(0 if failed == 0 else 1)
