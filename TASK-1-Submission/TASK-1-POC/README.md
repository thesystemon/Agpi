# TASK-1 PoC — SSRF → Remote Command Execution

This PoC demonstrates the Critical finding from `TASK-1-FINDINGS.md` (#1) and
`TASK-1-REPORT.md`: a Server-Side Request Forgery in the report/URL-fetch
feature that pivots into command execution on an internal service.

## Prerequisites

- Task 1 stack running locally:
  ```bash
  cd <task-1-source-folder>
  docker compose up -d
  ```
- Python 3.8+ with `requests`:
  ```bash
  pip install requests
  ```
- (For `probe` mode) a listener on your host to catch the outbound SSRF request:
  ```bash
  python3 -m http.server 8000
  ```
- A valid session cookie / account on the target app (`[FILL: how to obtain — e.g. register via /register]`)
- Internal service host/port confirmed from `docker-compose.yml` (`[FILL]`)

## Configuration

Open `exploit.py` and fill in the `CONFIG` block at the top:

| Variable | What to put |
|---|---|
| `BASE_URL` | The app's local URL, e.g. `http://localhost:5000` |
| `VULN_PATH` | Exact vulnerable route from source review |
| `SESSION_COOKIE` | A valid `session=...` cookie value (if the route requires auth) |
| `ATTACKER_LISTENER` | Your host's reachable address for the SSRF probe step |
| `INTERNAL_RCE_SINK` | The internal-only service address (Docker Compose service name) |
| `INJECTED_COMMAND` | Kept as `id` / `whoami` per the assessment's safe-PoC rules |

## Running the PoC

**Step 1 — Confirm SSRF (safe, no impact):**
```bash
python3 -m http.server 8000        # in one terminal
python3 exploit.py probe           # in another terminal
```
Expected: your `http.server` terminal shows an inbound `GET` request originating
from the application container, confirming the server made an outbound request
to an address you control.

**Step 2 — Escalate to command execution:**
```bash
python3 exploit.py exploit
```
Expected output:
```
[*] Response body (command output expected below):
------------------------------------------------------------
uid=1000(appuser) gid=1000(appuser) groups=1000(appuser)
------------------------------------------------------------
```
*(Actual output will reflect the real container user — capture this in a
screenshot for the report.)*

## Notes on Scope

This PoC stays within the assessment's rules of engagement:
- Only targets services started by the Task 1 Docker Compose file.
- No destructive payloads — only `id`/`whoami` is executed.
- No persistence mechanisms are installed.
- No attacks are made against the host machine or external infrastructure.

## Files

- `exploit.py` — the PoC script (probe + exploit modes)
- `screenshots/` — drop your evidence screenshots here (referenced from `TASK-1-REPORT.md`)
