# Repository bug review — 5 October 2026

Reviewed desktop orchestration, storage/audit operations, collectors, configuration,
tabular/capture analysis, scanning, credentials, exports, and existing tests.

## Fixed defects

- Preserve provider Retry-After cooldowns on the final HTTP attempt, including
  the single-attempt certificate lookup. Handle overflowing Retry-After dates.
- Refresh cache entries whose collection timestamp is in the future.
- Accept internationalized top-level domains and return a validation error for
  invalid IDNA labels. Reject malformed URL ports and embedded whitespace.
- Parse HTTP content types without depending on letter case.
- Reject certificate rows without name data, invalid HIBP breach dates, and OTX
  responses without association counts rather than presenting empty successes.
- Turn malformed provider types and DNS network failures into unavailable results.
- Query absolute DNS names without resolver search-suffix expansion.
- Preserve synthetic GPS rows when the import is classified as inferred.
- Reject empty CSV/XLSX column headers before pandas invents names.
- Refuse malformed TShark rows and invalid packet lengths/timestamps instead of
  silently skipping packets or returning misleading statistics.
- Report TShark launch failures with an actionable application error.
- Check the analysis hash and evidence hash again before saving results, refusing
  findings when evidence changes during processing.
- Serialize concurrent workspace-open audit writes to prevent chain forks.
- Validate acquisition timestamps and nonexistent watch cases explicitly.
- Reject invalid Nmap XML port numbers with an application validation error.
- Preserve discovered names and per-family results after DNS socket failures.
- Handle overflowing numeric configuration settings without an uncaught exception.

## Verification

- Before changes: **135 tests passed**.
- After changes: **167 tests passed**, including 32 new regression cases in
  `tests/test_review_regressions.py` and the real TShark synthetic-capture test.
- `pip check`: no broken requirements.
- `git diff --check`: passed.
- Installer and packaging shell scripts: `bash -n` passed.
- `scripts/verify_demo.py`: completed; three-page synthetic PDF and a valid audit
  chain. Generated screenshots, reports, and HTML are in ignored `artifacts/`.

Live external APIs, paid lookups, active target scans, installation, and packaged
bundles were not exercised. This review does not establish that every possible
defect has been eliminated.

## CyberRecon continuation review

Added a separate CyberRecon CLI/desktop workspace while retaining CyberIntel.
The implementation and outstanding specification work are documented in
[CYBERRECON.md](CYBERRECON.md).

Additional defects fixed during implementation:

- Block excluded public IPs returned by DNS, even when the hostname is included.
- Use absolute DNS names, avoiding search-suffix expansion in native requests,
  provider requests and the Go worker.
- Reject URL scope rules rather than broadening a path to a whole domain.
- Reject IPv6 addresses before passive domain engines are invoked.
- Preserve verified URL observations when another page links to the same URL.
- Keep HTTP relationships attached to the actual response host; unify explicit
  IP nodes across HTTP and port observations.
- Keep collection times, raw evidence paths and randomized negative controls
  from generating false scan-comparison changes.
- Bound compressed response output and reject redirects without destinations.
- Block credential forwarding across hosts; omit CSP nonces and digest values.
- Capture certificate metadata before connection closure and use the SSL API
  supported by httpcore; verify custom lab CAs without disabling TLS checks.
- Record scope changes with schema-1 migration to schema 2.
- Reject invalid scan exports before creating directories, and finish interrupted
  imports as failed rather than leaving permanent running records.
- Isolate optional-engine failures and terminate external process groups on
  cancellation; update desktop progress without blocking the UI.

Verification at this stage: **311 Python tests passed**, Go race tests passed,
and a real Nmap scan of a script-owned loopback HTTP/TLS service completed.
The TLS check collected four HTTP observations, one open port, two API records
and one JavaScript record, and generated JSON/CSV/HTML/PDF/graph reports.
No real-world targets or paid providers were queried. Shodan/Censys and NVD
contracts use mocked transports. Debian and signed development APT artifacts
are available, but clean Kali/Parrot installation, upgrade and uninstall remain
unverified; this is not a completed production release.

## CyberRecon full audit and hardening — 2026-10-07

See [docs/AUDIT.md](docs/AUDIT.md) for verified findings, adapter inventory,
remediation and remaining release limits, and [docs/SCHEMAS.md](docs/SCHEMAS.md)
for canonical data contracts. This phase preserves both existing applications.

Fixed resolved-IP scope bypasses in standalone active adapters, credential
redirects across ports, managed directory/evidence export protection, subprocess
limits/errors, multi-source/DNS normalization, interrupted scan recovery,
version/dependency Doctor checks and GUI blocking/detail gaps. Database schema 3
migrates existing projects and preserves scan history. Python >=3.12 is consistent.

Validation: 367 Python tests passed; three Go race tests and go vet passed;
loopback TLS/real Nmap, reports, offscreen GUI startup, Debian staging and local
development APT signing passed. Coverage percentage is unavailable. Actual clean
Kali/Parrot install/upgrade/remove and a graphical desktop session remain untested;
the added manually triggered distribution workflow is prepared but not executed.
These changes do not constitute production certification or hosted APT publication.

## Direct desktop scan setup

Removed the separate New project dialog. The scan form now accepts a target,
optional allowed/excluded scope and an authorization reference. Blank scope
defaults to the exact target; automatic internal contexts preserve scan history
and comparison. Invalid/excluded targets or missing authorization create no
context or active operation. CLI project commands remain compatible.
