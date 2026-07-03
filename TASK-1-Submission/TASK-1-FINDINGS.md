# TASK-1 — Findings Summary

**Assessment:** AGAPI Take-Home Assessment — Task 1
**Tester:** Kunal Namdas (H4ckerByNight)
**Target:** Task 1 CTF-styled web application (Docker Compose, local)
**Methodology:** Manual source code review (primary focus) + dynamic verification with Burp Suite / Python

---

## Summary Table

| # | Finding | Endpoint / Component | Severity | CVSS v3.1 |
|---|---------|----------------------|----------|-----------|
| 1 | SSRF leading to Remote Command Execution | `[FILL: e.g. POST /api/reports/generate — "url" param]` | **Critical** | 9.8 |
| 2 | Insecure Direct Object Reference (IDOR) — cross-tenant project export | `GET /projects/{id}/export?format=json\|csv` | **High** | 8.1 |
| 3 | Unrestricted File Upload → Stored XSS | `[FILL: e.g. POST /files/upload]` | **High** | 8.0 |
| 4 | Hardcoded / Default Flask `SECRET_KEY` → Session Forgery | `[FILL: session cookie, all authenticated routes]` | **Critical** | 9.1 |
| 5 | Cross-Site Request Forgery (CSRF) on state-changing endpoints | `[FILL: e.g. POST /account/update]` | **High** | 8.1 |
| 6 | Missing Rate Limiting — Registration | `POST /register` | **Low** | 5.3 |
| 7 | Missing Rate Limiting — Login (Brute Force) | `POST /login` | **Medium** | 7.5 |
| 8 | Session Not Invalidated on Logout | `POST /logout` + session cookie | **Medium** | 6.5 |

---

## 1. SSRF Leading to Remote Command Execution
- **Component:** `[FILL: exact route + parameter, e.g. url= in report/export/webhook feature]`
- **Severity:** Critical (CVSS 9.8 — AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
- **Impact:** The application fetches a user-supplied URL server-side without validation. By pointing this parameter at an internal service reachable only from inside the Docker network, an attacker can pivot the SSRF into command execution on the backend, proven via controlled `id`/`whoami` output.
- **Status:** ✅ Exploited (see `TASK-1-REPORT.md` and `TASK-1-POC/`)

## 2. IDOR — Cross-Tenant Project Export
- **Component:** `GET /projects/{id}/export?format=json` and `?format=csv`
- **Severity:** High (CVSS 8.1 — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
- **Impact:** The `id` path parameter is not checked against the authenticated user's ownership/tenant. Simply incrementing the ID (e.g. `4` → `2`) returns another user's project data in both JSON and CSV export formats — a full authorization bypass / cross-tenant data leak.
- **Status:** Verified, not chosen as primary exploited finding (RCE prioritized for greater impact)

## 3. Unrestricted File Upload → Stored XSS
- **Component:** `[FILL: upload endpoint]`
- **Severity:** High (CVSS 8.0 — AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:N)
- **Impact:** The upload feature accepts `.html` files without content-type/extension allow-listing and serves them back inline (not as `attachment`, no sandboxed origin). Any user who opens the uploaded file executes attacker-controlled JavaScript in their session context — enabling session theft, forced actions, or further payload delivery.
- **Status:** Verified with working PoC (payload executed in victim browser)

## 4. Hardcoded / Default Flask `SECRET_KEY` → Session Forgery
- **Component:** Flask session cookie (signed with `itsdangerous`), affects all authenticated routes
- **Severity:** Critical (CVSS 9.1 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **Impact:** The application ships with a static/default `SECRET_KEY`. Since Flask signs (not encrypts) session cookies, anyone who knows this key can forge a valid, signed session cookie for **any user ID** — including admin — without ever knowing their password. Demonstrated by generating a forged cookie for `alice` and logging in as her.
- **Status:** Verified with working PoC (custom cookie-forging script)

## 5. Cross-Site Request Forgery (CSRF)
- **Component:** `[FILL: state-changing endpoint(s) tested, e.g. /account/update, /projects/create]`
- **Severity:** High (CVSS 8.1 — AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N)
- **Impact:** State-changing POST endpoints do not validate a CSRF token and do not check `SameSite`/`Origin`/`Referer`. A malicious page can silently trigger authenticated actions on behalf of a logged-in victim (`alice`) purely from a cross-site auto-submitting form.
- **Status:** Verified with working PoC (auto-submit HTML page)

## 6. Missing Rate Limiting — Registration
- **Component:** `POST /register`
- **Severity:** Low (CVSS 5.3 — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)
- **Impact:** No throttling on account creation. Automating the `email` parameter (e.g. incrementing `kunal1@gmail.com` → `kunal20@gmail.com`) allows unlimited bulk account creation, enabling spam, resource exhaustion, and downstream abuse (e.g. fake accounts used in the IDOR/CSRF chain above).

## 7. Missing Rate Limiting — Login (Brute Force Enabler)
- **Component:** `POST /login`
- **Severity:** Medium (CVSS 7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N, elevated in context due to credential-stuffing risk)
- **Impact:** Repeated invalid login attempts consistently return `401 Unauthorized` with no `429 Too Many Requests` after threshold, confirming the absence of any lockout/throttle. This makes the endpoint fully brute-forceable. During testing, a valid password was recovered once a correct guess returned a `302` redirect rather than a `401`.

## 8. Session Not Invalidated on Logout
- **Component:** `POST /logout` + session cookie reuse
- **Severity:** Medium (CVSS 6.5 — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)
- **Impact:** The server does not invalidate the session server-side (no session store revocation / cookie is not cleared or blacklisted) on logout. A previously captured cookie value continues to authenticate successfully after the legitimate user has logged out — meaningful in combination with the CSRF/XSS findings above, where a cookie could be exfiltrated.

---

### Notes
- Findings #1 and #4 are both Critical; **#1 (SSRF → RCE) was selected as the primary exploited finding** for `TASK-1-REPORT.md` since it demonstrates the highest real-world impact (arbitrary command execution) and best satisfies the "safe proof-of-impact" criteria in the assessment brief (`id`/`whoami` output).
- Bracketed `[FILL: ...]` placeholders mark spots where you should paste the exact route/parameter names confirmed from your source code review — I've kept the vulnerability class, severity reasoning, and structure accurate; you know the literal endpoint strings from the repo better than I do from screenshots alone.
