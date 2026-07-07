"""
=============================================================
  DEMO: Rate Limiting & Account Lockout in Action
=============================================================
  Run this while the server is up:  python demo_lockout.py
"""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import requests, time, uuid

BASE = "http://127.0.0.1:5000"
uid = uuid.uuid4().hex[:6]
USER = f"demo{uid}"
EMAIL = f"demo{uid}@test.com"
PASSWORD = "DemoPass123"

def post(url, data):
    return requests.post(url, json=data, timeout=30)

def divider(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")

# ── Setup ─────────────────────────────────────────────────
divider("SETUP: Creating test user")
r = post(f"{BASE}/api/auth/register", {
    "username": USER, "email": EMAIL, "password": PASSWORD
})
print(f"  Created user: {USER}")
print(f"  Password:     {PASSWORD}")
print(f"  Status:       {r.status_code}\n")

# Verify login works
r = post(f"{BASE}/api/auth/login", {"username": USER, "password": PASSWORD})
print(f"  Login with correct password: {r.status_code} -> {r.json().get('error', 'SUCCESS - got token')}")

# ──────────────────────────────────────────────────────────
divider("DEMO 1: Progressive Delay")
print("  Each wrong password attempt takes LONGER to respond.\n")

for i in range(1, 6):
    start = time.time()
    r = post(f"{BASE}/api/auth/login", {"username": USER, "password": "WrongPass999"})
    elapsed = time.time() - start
    bar = "#" * int(elapsed * 10)
    print(f"  Attempt {i}: {elapsed:5.2f}s  {bar}  (status={r.status_code})")

# ──────────────────────────────────────────────────────────
divider("DEMO 2: Account Lockout (5 fails = locked)")
print("  After 5 consecutive failures, the account is LOCKED for 15 minutes.")
print("  Even the CORRECT password is rejected!\n")

# The 5 attempts above already triggered the lock. Try correct password:
start = time.time()
r = post(f"{BASE}/api/auth/login", {"username": USER, "password": PASSWORD})
elapsed = time.time() - start
print(f"  Login with CORRECT password: {r.status_code}")
print(f"  Response: \"{r.json().get('error', 'no error')}\"")
print(f"  Time: {elapsed:.2f}s")
print(f"\n  --> Account is LOCKED! Correct password still rejected.")

# ──────────────────────────────────────────────────────────
divider("DEMO 3: Indistinguishable Responses")
print("  Wrong password, locked account, and non-existent user")
print("  all return the SAME response. Attackers can't tell them apart.\n")

r1 = post(f"{BASE}/api/auth/login", {"username": USER, "password": "WrongPass999"})
r2 = post(f"{BASE}/api/auth/login", {"username": USER, "password": PASSWORD})
r3 = post(f"{BASE}/api/auth/login", {"username": "nonexistent_user_xyz", "password": "Whatever1"})

print(f"  Wrong password:     status={r1.status_code}  msg=\"{r1.json().get('error')}\"")
print(f"  Correct but locked: status={r2.status_code}  msg=\"{r2.json().get('error')}\"")
print(f"  Non-existent user:  status={r3.status_code}  msg=\"{r3.json().get('error')}\"")

all_same = (r1.status_code == r2.status_code == r3.status_code and
            r1.json().get('error') == r2.json().get('error') == r3.json().get('error'))
print(f"\n  All identical? {'YES - attackers learn nothing!' if all_same else 'Responses differ (rate limit may have kicked in)'}")

# ──────────────────────────────────────────────────────────
divider("DEMO 4: IP Rate Limiting (max 10 requests/minute)")
print("  After 10 login attempts from the same IP in 1 minute,")
print("  the server returns 429 Too Many Requests.\n")

hit_429 = False
for i in range(1, 8):
    r = post(f"{BASE}/api/auth/login", {"username": "probeuser", "password": "x"})
    status = r.status_code
    print(f"  Request {i}: status={status}", end="")
    if status == 429:
        retry = r.headers.get('Retry-After', '?')
        print(f"  --> RATE LIMITED! Retry-After: {retry}s")
        hit_429 = True
        break
    else:
        print()

if not hit_429:
    print("\n  (Rate limit not hit yet - you may need to send more requests)")

# ──────────────────────────────────────────────────────────
divider("DEMO 5: Server-Side Logs")
print("  Check your server terminal! You should see log lines like:\n")
print('  WARNING - account locked username=demoXXXXXX ip=127.0.0.1 fail_count=5')
print('  WARNING - login rate-limited ip=127.0.0.1 (>10/60s)')
print('  INFO    - lockout email skipped (SMTP unconfigured)')
print('  WARNING - Auth input validation failure on /api/auth/login ...')
print(f"\n  Look for username={USER} in the server output.\n")

divider("DONE")
print("  All features demonstrated! Check your server terminal for the logs.\n")
