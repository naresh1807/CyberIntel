# CyberIntel Suite function review — 5 October 2026

The reviewed desktop workflows pass automated verification after the fixes below. This report does not claim that every external provider or deployment target is available or verified.

## Results

- **97 tests passed, 1 skipped**, Python 3.12.10 on Windows (including the subsequent subdomain-address fix).
- Dependencies: `pip check` reports no broken requirements.
- Python compilation: application, scripts and tests pass `compileall`.
- Rendered desktop/dashboard/CDR/phone/subdomain previews and a three-page synthetic PDF were checked. Synthetic subdomain previews are explicitly labeled.
- The 100,000-row synthetic CDR benchmark completes in **1.029 seconds**, with totals verified. This is a single-machine measurement, not a general performance guarantee.
- Machine-readable test output: `artifacts/test-results.xml`.

## Workflow coverage

| Function / workflow | Verification | Result / limitation |
| --- | --- | --- |
| First-launch administrator / subsequent login | Actual dialog handlers, password clearing, hash checks | Pass |
| Password lockout / expired lockout | Database + authentication regression | Pass; expiry grants a new failure budget |
| Role access / revocation | Backend permission checks and desktop refresh | Pass; revoked admin role clears the users table |
| Case creation / selection | Dialog handlers, repository and desktop | Pass; changing cases clears transient results |
| Evidence import / provenance / SHA-256 | Actual import handler, managed copy, tamper checks | Pass; original synthetic inputs remain unchanged |
| Tables / sorting / filtering | Desktop models and proxy checks | Pass; numeric values sort numerically |
| DNS collection | Live example.com + controlled exceptions | Live success |
| RDAP | Live example.com and response checks | Live success |
| Public website metadata | Live example.com and parser test | Live success; title `Example Domain` |
| Certificate transparency / subdomains | Controlled source, wildcard/scope/cache tests; live example.com | Automated workflow passes; crt.sh returned HTTP 502 during this audit |
| Subdomain DNS / CSV | Automatic enrichment in both views, A/AAAA, no-answer/NXDOMAIN/timeouts, limits, filter/export checks | Pass; independent live DNS check of www.example.com returned both IPv4 and IPv6. Live CT discovery remains unavailable during the earlier check |
| HIBP public catalog | Live provider + malformed/404 tests | Live success |
| HIBP email / verified domain exposure | Authenticated request-contract fixtures, normalization and privacy checks | Pass with fixtures; no live account key supplied |
| Breach watches / alerts | Actual desktop worker, baseline/new names/increased counts/failure behavior | Pass with fixtures |
| OTX enrichment | Request-contract, severity and malformed-response fixtures | Pass with fixtures; no live account key supplied |
| URLhaus enrichment / feed | Request-contract, metadata-only normalization and desktop feed worker | Pass with fixtures; no live Auth-Key supplied |
| CSV/XLSX CDR | Synthetic calculations, bad durations/timestamps, duplicate columns, size checks | Pass |
| Relationship graph | Small and >500-node graph generation; desktop browser-open handoff | Pass; large graphs no longer depend on missing SciPy |
| Offline PCAP | Simulated TShark process, bad magic, missing tool, expected command/parsed data | Adapter checks pass; real TShark test skipped because executable is absent |
| GPS / tower import | Coordinates/provenance and desktop import/analysis checks | Pass |
| Maps | HTML output, popup escaping, desktop browser-open handoff | Pass; remote CDN/tile availability is not an offline guarantee |
| Phone region estimate | Public metadata, invalid inputs, example mobile/landline, desktop case saving | Pass; provides allocation metadata, not device location |
| PDF / CSV case report | Actual desktop export, file roundtrip, rendering, evidence inventory | Pass |
| Audit chain | Mutation detection and successful workflow consistency | Pass; no external anchoring is claimed |
| Credential vault | Encrypt/reopen/wrong-passphrase/corruption/save failure, desktop lock/unlock | Pass |
| Settings / users | Actual credential and user-creation handlers | Pass |
| Background workers | GUI-thread callbacks, success/failure recovery, selector lock | Pass |
| Configuration / CLI | BOM, invalid schemas/endpoints, clean nonzero startup errors | Pass |
| Future database schema | Reject newer schema without changing its version | Pass |
| Kali/Ubuntu installer / PyInstaller scripts | Source/configuration review | Actual Linux install and packaged bundle remain unverified; WSL is absent here |

## Bugs fixed

1. Results from the previous case remained visible and could be reused after selecting another case. Case changes now clear those results; case selection is disabled during background jobs, and creating/changing cases or restoring findings is guarded while a job runs.
2. Numeric table values sorted as text (`1, 10, 2`). The proxy now uses native numeric sort data.
3. Unexpected HIBP domain response shapes could become an apparent zero-exposure success. HIBP/OTX/URLhaus responses now receive shape validation. Public HIBP catalog 404 is treated as failure, while authorized account/domain 404 retains its documented empty-result meaning.
4. Provider cooldowns were lost across collections, and NaN/infinite/negative Retry-After values could break retry handling. Cooldowns persist and malformed values use bounded retry delays.
5. NetworkX's layout for graphs of 500+ nodes required undeclared SciPy. Large bounded graphs use deterministic circular layout; smaller graphs retain spring layout.
6. Empty/truncated credential files were treated as newly created vaults. They are now rejected. Vault saves use private temporary files, commit atomically and leave in-memory values unchanged if saving fails.
7. A damaged cache entry could block collection. Invalid JSON/result timestamps are discarded so a fresh request can proceed.
8. Configuration errors produced startup tracebacks, BOM configuration failed, and opening a newer database silently reset its version. Configurations now receive explicit validation and actionable startup errors; newer schemas are rejected without downgrade.
9. Expired login lockouts retained the old failure count and could immediately re-lock on a single bad attempt. Expired locks now reset the failure budget.
10. Duplicate watches and a 26th watch could disable the whole monitor batch. The backend now normalizes targets, rejects duplicates and enforces the limit when adding watches.
11. Failed monitor requests updated `last_checked` as though they succeeded; alerts missed increased exposure counts in an existing breach. Only live success updates that timestamp, and count increases now trigger alerts. Timer ticks with no selected case are ignored.
12. Pandas renamed identical input column names before duplicate detection. CSV/XLSX headers are checked first, before loading the table.
13. Folium popup text escaped HTML but could still interpolate JavaScript template syntax. Backticks and dollar signs are escaped as well.
14. Report/subdomain exports could overwrite managed evidence or application state, and a failed export could damage an existing report. Destinations are protected, and report/visual/CSV outputs commit through temporary files after successful generation.
15. A cached session role could leave the admin users table visible after revocation. Permission checks update the session role, and the UI clears that table for non-admin users.
16. Analyzer functions accepted arbitrary provenance kinds, blank tower IDs and empty map data. These inputs now fail explicitly.

## Reproduce

Subdomain address follow-up: discovery previously required a separate DNS action, and wide provenance columns placed address columns off-screen. The first 100 discovered names now receive automatic DNS enrichment by default, with IPv4/IPv6 next to the hostname and explicit per-family absence/failure labels. Larger discoveries leave remaining rows visibly `Not checked`. Resolver configuration failures preserve discovered names and show errors. The optional live check `scripts/check_subdomain_addresses.py` records actual A/AAAA answers in `artifacts/subdomain-address-check.json`, independently of crt.sh availability.

```powershell
.\.venv\Scripts\python.exe -m pytest -q --junitxml artifacts/test-results.xml
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m compileall -q cyberintel scripts tests
.\.venv\Scripts\python.exe scripts/verify_demo.py
.\.venv\Scripts\python.exe scripts/benchmark_cdr.py
# Optional public live checks; network access required:
.\.venv\Scripts\python.exe scripts/check_public_sources.py
.\.venv\Scripts\python.exe scripts/check_website.py
.\.venv\Scripts\python.exe scripts/check_subdomains.py
```

Use `.venv/bin/python` equivalents on Linux. For a real PCAP run, install TShark and rerun the skipped test. Credentialed provider checks require your authorized keys/subscriptions. No real subscriber records, stolen databases, private telecom access or live packet capture were used in this review.


## Production release preparation

The Debian 0.2.0-5 candidate retains CyberRecon 0.2.0 and CyberIntel compatibility.
MIT is selected; public maintainer identity and HTTPS APT hosting remain unavailable.
See [production readiness](docs/PRODUCTION_RELEASE_READINESS.md),
[release checklist](docs/RELEASE_CHECKLIST.md), [APT/signing operations](docs/APT_REPOSITORY.md),
and [compatibility migration plan](docs/COMPATIBILITY_MIGRATION.md).
Desktop VM, reboot and production publication gates remain blocked or untested.


## Final v0.2.0 release gate

Baseline c1fafb8 plus local final-gate changes: 410 tests passed, zero failures/skips/xfailed.
Live Kali source GUI/CLI and owned TLS/Nmap checks passed. Installed Kali/Parrot
desktop lifecycle, reboot and production distribution remain BLOCKED/NOT TESTED.
See [final decision](docs/PRODUCTION_RELEASE_READINESS.md). Earlier Windows and
revision-3/4 results are historical evidence for their own versions/environments.
