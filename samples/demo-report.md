# ReconLedger lab assessment

## Run summary
- **started:** 29 Oct 2026 16:08 IST
- **target:** 127.0.0.1 ports 3000,4280 (localhost lab)
- **scope allow-list:** 127.0.0.0/8, ::1/128, localhost
- **active steps approved / asked:** 2 / 2
- **executed:** nmap_scan, header_check
- **skipped (denied/no tool):** none
- **blocked by scope guard:** header_check -> http://example.com/
- **tool errors:** none
- **findings:** 5

## Ranked findings

| # | Score | Target | Finding | Sources |
|---|---|---|---|---|
| 1 | 7.0 | 127.0.0.1:3000 | Missing Content-Security-Policy | headers |
| 2 | 6.5 | 127.0.0.1:3000 | CORS allows any origin (Access-Control-Allow-Origin: *) | headers |
| 3 | 5.5 | 127.0.0.1:3000 | Open port 3000/tcp (service guess: ppp) | nmap |
| 4 | 5.0 | 127.0.0.1:3000 | Served over plain HTTP (no TLS) | headers |
| 5 | 3.0 | 127.0.0.1:3000 | Missing Referrer-Policy | headers |

## Why each finding ranks where it does

**1. Missing Content-Security-Policy** (7.0)
- correlated: nmap confirms 127.0.0.1:3000 is open and reachable
- base severity 5.0
- confirmed-reachable: port scan confirms the weak service is actually reachable
- xss-surface: missing CSP leaves injected scripts unrestricted
- **fix:** Add a restrictive Content-Security-Policy (default-src 'self').

**2. CORS allows any origin (Access-Control-Allow-Origin: *)** (6.5)
- correlated: nmap confirms 127.0.0.1:3000 is open and reachable
- base severity 5.0
- confirmed-reachable: port scan confirms the weak service is actually reachable
- cors-wide-open: any website can read responses from this app
- **fix:** Restrict Access-Control-Allow-Origin to trusted origins.

**3. Open port 3000/tcp (service guess: ppp)** (5.5)
- correlated: 4 web weaknesses found behind this port
- base severity 3.0
- listening-service: service is listening and reachable
- port-with-weaknesses: open port fronts an app with misconfigurations

**4. Served over plain HTTP (no TLS)** (5.0)
- correlated: nmap confirms 127.0.0.1:3000 is open and reachable
- base severity 4.0
- confirmed-reachable: port scan confirms the weak service is actually reachable
- **fix:** Terminate TLS in front of the app and redirect HTTP to HTTPS.

**5. Missing Referrer-Policy** (3.0)
- correlated: nmap confirms 127.0.0.1:3000 is open and reachable
- base severity 2.0
- confirmed-reachable: port scan confirms the weak service is actually reachable
- **fix:** Add Referrer-Policy: strict-origin-when-cross-origin.
