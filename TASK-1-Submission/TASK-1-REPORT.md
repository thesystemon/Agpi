# TASK-1 — Penetration Test Report

## SSRF Leading to Remote Command Execution

| | |
|---|---|
| **Target** | AGAPI Task 1 — CTF-styled web application (local Docker Compose) |
| **Tester** | Kunal Namdas (H4ckerByNight) — Offensive Security Specialist |
| **Date** | `[FILL: test date]` |
| **Vulnerability Class** | CWE-918 (SSRF) chained to CWE-78 (OS Command Injection) |
| **Severity** | Critical — CVSS 3.1: 9.8 |
| **Status** | Exploited — verified working PoC |

---

## 1. Executive Summary

- The application exposes a feature at **`[FILL: exact route, e.g. POST /api/reports/generate]`** that accepts a user-controlled `url` parameter and fetches it **server-side** with no allow-listing, scheme restriction, or network-egress control.
- This Server-Side Request Forgery (SSRF) allows an attacker to reach services on the internal Docker network that are **not exposed externally**.
- One of these internal services processes the fetched content in a way that passes attacker-controlled data into a shell command without sanitization, resulting in **full remote command execution** on the backend container.
- Impact was proven safely and non-destructively by executing `id` / `whoami` inside the container and capturing the output — no destructive payloads, no host escape, no data was modified.
- This is the **most impactful finding** of the assessment: it moves from unauthenticated/low-privilege HTTP access to full code execution in the trust boundary of the application.
- **Recommendation priority: Immediate.** Fix both the SSRF entry point (outbound request validation) and the downstream command construction (root cause) — patching only one leaves the other exploitable.

---

## 2. Technical Details

### 2.1 Root Cause

`[FILL from source code review — replace this paragraph with the actual code-level root cause]`

Typical root cause pattern observed in this vulnerability class (confirm against actual source):

```python
# Illustrative — replace with actual vulnerable code snippet + file path/line number
@app.route("/api/reports/generate", methods=["POST"])
def generate_report():
    target_url = request.json.get("url")
    response = requests.get(target_url)          # <-- no scheme/host allow-list (SSRF sink)
    ...
    subprocess.run(f"process_report {response.text}", shell=True)  # <-- unsanitized input to shell (RCE sink)
```

Two distinct root causes combine into one exploit chain:
1. **No validation of the `url` parameter** before the server issues an outbound request (missing scheme allow-list, no block on `127.0.0.1` / `169.254.0.0/16` / internal Docker service names / `file://`, `gopher://`, etc.).
2. **Unsanitized use of fetched/derived data in a shell command context** (`subprocess` with `shell=True`, or equivalent), which turns the SSRF into command injection once an attacker controls what the internal service returns or is invoked with.

### 2.2 Impacted Components

| Component | Role |
|---|---|
| `[FILL: route/file, e.g. app/routes/reports.py]` | SSRF entry point — accepts and forwards the `url` parameter |
| `[FILL: internal service name / container, e.g. internal-worker container]` | RCE sink — executes shell command using SSRF-fetched data |
| Docker internal network | Enables the SSRF pivot to a service not reachable from outside |

---

## 3. Reproduction Steps

**Prerequisites:**
- Task 1 stack running locally (`docker compose up -d`)
- Any valid authenticated session (or unauthenticated, if the endpoint requires none — `[FILL]`)
- Burp Suite / curl / Python `requests`

**Steps:**

1. Log in / obtain a session as any low-privilege user.
2. Identify the vulnerable request:
   ```
   [FILL: exact method + path + body, e.g.]
   POST /api/reports/generate HTTP/1.1
   Host: localhost:PORT
   Content-Type: application/json
   Cookie: session=<valid_session>

   {"url": "http://example.com/report.json"}
   ```
3. Confirm SSRF first (safe, non-destructive) by pointing `url` at an attacker-controlled listener (e.g. `python3 -m http.server`, or a `requestbin`-style catcher) and confirming an inbound hit from the server.
4. Confirm internal reachability by pointing `url` at internal-only hosts/ports discovered via the Docker Compose file (service names resolve inside the Compose network, e.g. `http://internal-worker:PORT/...`).
5. Escalate to command execution by crafting the request so the internal service's response/behavior is passed unsanitized into the shell sink identified in §2.1, injecting a benign command (`id`, `whoami`) as the proof of impact.
6. Observe command output returned in the HTTP response / logs, confirming code execution inside the container.

**Screenshot placeholders — replace with your evidence:**

![Screenshot: Burp Suite request showing the vulnerable url parameter](screenshots/01-ssrf-request-burp.png)

![Screenshot: SSRF confirmed - internal service reached](screenshots/02-ssrf-internal-hit.png)

![Screenshot: Command injection - id/whoami output returned](screenshots/03-ssrf-rce-output.png)

---

## 4. Exploit / PoC

A reusable script is provided in `TASK-1-POC/exploit.py` (see `TASK-1-POC/README.md` for run instructions). Summary of how it works:

1. Sends a POST request to the vulnerable endpoint with an attacker-controlled `url`.
2. First runs in **"probe" mode** — points at a local listener to confirm SSRF blind-fire (safe, no impact).
3. Then runs in **"exploit" mode** — points the SSRF at the internal RCE sink with an injected `id` command, and prints the command output extracted from the HTTP response.

**Expected output (proof):**
```
[+] SSRF confirmed: outbound request received from target server
[+] Pivoting to internal service: [FILL: internal host:port]
[+] Command injected: id
[+] Response:
uid=[FILL] gid=[FILL] groups=[FILL]
```

*(Replace the sample output above with the real captured output from your test run.)*

![Screenshot: PoC script execution and output](screenshots/04-poc-execution.png)

---

## 5. Remediation

### 5.1 Fix Tied to Root Cause
- **Do not allow user input to determine the destination of a server-side HTTP request.** If fetching arbitrary URLs is a required feature, enforce a strict allow-list of permitted hosts/schemes; reject `http(s)` requests to RFC1918 ranges, `169.254.169.254` (cloud metadata), `localhost`, and internal Docker service names.
- **Never build shell commands via string interpolation of external/derived input.** Replace `subprocess.run(..., shell=True)` with `subprocess.run([...], shell=False)` using a fixed argument list, and validate/whitelist any values that must be passed through.
- Validate and canonicalize the `url` parameter server-side (resolve DNS before connecting and re-check the resolved IP against the deny-list, to prevent DNS-rebinding bypass of an allow-list).

### 5.2 Defense-in-Depth
- Run the outbound-fetch functionality in an isolated/sandboxed egress path (e.g. a proxy that only permits pre-approved destinations), separate from services with shell/command execution capability.
- Apply network segmentation so internal-only services are not reachable from the component that accepts untrusted input, even within the Docker network.
- Run backend containers with least-privilege (non-root user, read-only filesystem where possible) to limit blast radius if command execution is achieved.
- Add outbound request logging/alerting for requests to internal IP ranges from user-facing services.
- Regularly run SAST/dependency scanning to catch `shell=True` / unsanitized `subprocess` patterns in CI.

---

*Report prepared by Kunal Namdas — Offensive Security Specialist. Findings #2–8 are documented in `TASK-1-FINDINGS.md`; this report covers the primary exploited finding as required by the assessment brief.*
