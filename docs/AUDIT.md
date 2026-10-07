# CyberRecon code audit

Audit baseline: Git commit 5718fdb. Scope: both Python packages, Go DNS worker,
CLI/GUI, SQLite, adapters, parsers, tests, scripts, workflow and documentation.
This is a source audit plus local verification, not production certification.
No third-party targets are scanned. Findings below were recorded before fixes.

## 1. Architecture

CyberRecon is an incremental second entry point beside CyberIntel. CLI and
PySide6 workers call scanner.scan, with Repository SQLite/WAL persistence and
per-scan JSON. ScopedHTTP validates scope, pins resolved addresses, verifies TLS,
redacts query values and bounds responses. Scope includes domains, wildcards,
IPs/CIDRs and exclusions. Native DNS, bounded crawling/content discovery,
external passive discovery and explicit-IP Nmap feed observation tables.
Optional lifecycle/NVD and existing-host providers enrich observations.
Go is an optional bounded DNS subprocess, not required for operation.
CyberIntel remains a separate case/evidence application; its explicit consent
checks are not equivalent to CyberRecon's project scope policy.

## 2. Implemented features

Authorization references and scope history; exclusions; native DNS/HTTP/TLS;
passive CT/Subfinder/Assetfinder/Amass v3; historical gau/waybackurls; explicit-IP
Nmap TCP/UDP; API-document/JS extraction; JSONL imports; SQLite snapshots;
comparison; JSON/CSV/HTML/PDF; offline graph; desktop workers/cancellation;
Shodan/Censys existing observations; conservative lifecycle/CVE candidates.
Evidence is hashed; bodies, cookie values and provider keys are not persisted
by native collection. Imports remain unverified; absence is not proof of safety.

## 3. Partially implemented features

Doctor only checks PATH. Observation schemas use dictionaries and per-kind
keys, without unified multi-source provenance. Relationships are attributed,
but the displayed graph is undirected and evidence is hover-only. Optional
engine failures become string warnings, rather than structured categories.
WhatWeb/ffuf functions exist but are disconnected from the scanner; they do
not provide native DNS safety. Package/repository builders work locally but
clean distribution installation is not proven.

## 4. Missing features

Gobuster integration; active orchestration of dnsx/httpx/Naabu/Katana (imports
exist); authenticated API assessment; resumable scheduling; vendor/backport
CVE applicability; full external-engine compatibility fixtures; clean Kali and
Parrot installation/upgrade/removal verification; production license,
maintainer identity, signing trust root and hosted APT repository.

## 5–9. Verified findings

| ID | Severity | Evidence and implication | Priority |
| --- | --- | --- | --- |
| S1 | HIGH | engines.fingerprint/content_scan check hostname then delegate DNS to WhatWeb/ffuf; excluded/private resolved IP policy can be bypassed through these callable adapters. | 1 |
| S2 | HIGH | ScopedHTTP credentialled redirects compare hostname only: a different port on the same hostname receives Authorization headers. | 1 |
| S3 | HIGH | Repository.evidence/start_scan follow symlinked managed scans/evidence directories; writes can leave the managed workspace. | 1 |
| S4 | MEDIUM | Repository.export_json accepts a managed evidence directory and can replace a raw artifact named assets.json with an export. | 1 |
| R1 | MEDIUM | run_process merges timeout/cancel/output failures, misses final stderr size, and does not supervise engine-owned Nmap XML while running. | 2 |
| R2 | MEDIUM | Repository.save replaces provenance and permits attributes.key to override stored key; imported DNS keys differ from native hashed keys. | 2 |
| R3 | MEDIUM | Hard interruption leaves scans running indefinitely; no explicit recovery command. KeyboardInterrupt bypasses scanner cleanup. | 2 |
| R4 | MEDIUM | Doctor has no version/compatibility/dependency/permission/config checks; GUI will need background probing once upgraded. | 2 |
| R5 | MEDIUM | Existing workspace permissions are not tightened before SQLite opens; sidecar symlinks are not checked. | 2 |
| R6 | MEDIUM | DNSX parser appends partial row data before a later family fails; no IP-family validation. | 2 |
| R7 | MEDIUM | HTTP warnings interpolate arbitrary exception strings, which can expose provider parameters; NVD bypasses ScopedHTTP via legacy Collector. | 2 |
| P1 | MEDIUM | socket.getaddrinfo has no explicit deadline; Python DNS is serial and a Go job uses a scope snapshot until cancelled. | 3 |
| P2 | MEDIUM | Large graph/report/export and GUI table population run synchronously, with snapshots repeatedly decoded; no profiling evidence yet. | 3 |
| D1 | LOW | Python requirement is 3.11 in metadata/installer but 3.12 in Debian and CyberRecon docs; README prioritizes Ubuntu. | 2 |
| D2 | LOW | Graph drops edge direction and provides no click-to-evidence navigation. | 3 |
| D3 | LOW | GUI row details use 10,000-character tooltip strings, silently truncating evidence details. | 3 |

Baseline severity totals: CRITICAL 0, HIGH 3, MEDIUM 10, LOW 3. These are
verified development gaps, not claims that an external target is vulnerable.

## 8. Test coverage gaps

Existing tests cover core scope, redirect blocking, response bounds, parsers,
providers, reports, migrations and mock workflows. Missing regressions include
credential redirects across ports, managed-directory symlinks, process final
stderr/file caps, version-aware Doctor, multi-source normalization, partially
invalid DNS import rows, interrupted recovery and package lifecycle staging.
No coverage percentage was recorded at baseline. External engine version
compatibility and clean Parrot lifecycle remain unvalidated.

## 9. Packaging/release assessment

Debian has a fixed launcher, distro dependencies, desktop entry and no
maintainer scripts that delete workspaces or install via pip. Its placeholder
maintainer/license are explicitly development-only. Signed APT creation is
local, with short-lived development signing support. A built package does not
prove apt dependency resolution, GUI libraries or distro lifecycle behavior.
CI is hosted on Ubuntu and needs supported-distribution test jobs. Never claim
`apt install cyberrecon` from public repositories until hosting/trust exists.

## 10. Recommended priority

First close active scope/credential/file-write gaps. Then improve subprocess
limits, normalization, recovery and Doctor with regressions. Validate complete
suite and loopback TLS/Nmap pipeline, GUI startup and package staging. Finish
with distribution release qualification; deferred requirements stay explicit.

## Remediation and validation

Updated at completion with fixes, remaining limits and measured checks.

### Adapter verification matrix

All runtime subprocess adapters use fixed argv, bounded input/output, deadlines,
process-group cancellation and safe error categories. Build/signing subprocesses
also have deadlines. Installed status below is the observed local Doctor result;
probe failures can reflect workspace restrictions or tool configuration and do
not establish that the same installation fails outside this environment.

| Tool | Local probe | Version policy | Builder/parser | Scope and wiring | Evidence/tests |
| --- | --- | --- | --- | --- | --- |
| CT providers | not a binary | Fixed provider bridge | concrete-name filtering | passive scanner stage | historical names, mock fallback tests |
| Subfinder | executable; probe failed | >=2.6,<3 CLI family | fixed passive flags / domain lines | selected passive stage, scoped input/output | normalized observations; live provider qualification pending |
| Assetfinder | missing | no dependable version-only interface | fixed passive flags / domain lines | selected passive stage | manual version review needed |
| Amass | executable; probe failed | v3 only, enforced before enumeration | fixed passive flags / domain lines | selected passive stage | unsupported-version regression |
| Nmap | 7.99 READY | >=7,<8 CLI family | fixed IP argv / bounded XML parser | selected TCP/UDP stage; no inferred IP authorization | raw hashed XML, real own-loopback TCP test; UDP live test pending |
| dnsx | missing | >=1,<2 import format family | JSONL parser | import only, no active tool execution | DNS normalization/invalid-row tests |
| ProjectDiscovery httpx | executable; probe failed | >=1,<2; unrelated Python CLI rejected/reviewed | JSONL parser | import only | scoped/status/redaction tests |
| Naabu | missing | >=2,<3 import format family | JSONL parser | import only | bounded port import tests |
| Katana | executable; probe failed | >=1,<2 import format family | JSONL parser | import only | URL import tests |
| gau | missing | >=2,<3 CLI family | fixed history flags / sanitized URLs | selected history stage | normalized URLs; live historical engine fixtures pending |
| waybackurls | missing | manual version review | fixed stdin / sanitized URLs | selected history stage | normalized URLs; live qualification pending |
| ffuf | 2.1 READY | >=2,<3 CLI family | safe native adapter replacement | external execution disabled; native discovery is wired | resolved-IP exclusion regression |
| WhatWeb | 0.6.4 READY | >=0.5,<1 CLI family | safe native banner adapter replacement | external execution disabled; native banners are wired | resolved-IP exclusion regression |
| Gobuster | executable; probe failed | >=3,<4 CLI family | not implemented | not wired | explicit pending status |
| Go DNS | rebuilt 0.2.0 READY | >=0.2,<1 protocol family | fixed binary / validated NDJSON | optional stage, scoped snapshot | protocol tests, three Go race tests, go vet |

### Fixed issues

- S1: standalone active adapters use native ScopedHTTP, retaining their public
  interfaces. External ffuf/WhatWeb DNS execution is intentionally disabled.
- S2: credentials/parameters cannot cross HTTP origins, including port changes;
  explicit default port remains the same origin.
- S3: internal scan/evidence/export path components reject symlinks. Evidence
  names reject dot components; invalid scans cannot construct output paths.
- S4: reports cannot overwrite managed raw evidence directories.
- R1: process failures have stable categories; input/argv, stdout/stderr and
  engine-owned output files are bounded; final output is checked; cancellation
  and timeout kill the process group. Nmap output addresses/protocols are checked,
  with bounded rate/parallelism. Amass requires a successfully probed v3 version.
- R2: serialized upserts preserve canonical keys, stable fact IDs, first/last
  times and multi-source attribution. Native/imported DNS share canonical
  address/name/MX identities. Positive verification is not downgraded by a
  later unverified observation within the same current scan.
- R3: Ctrl-C cancels/preserves the native scan; explicit recover marks abandoned
  running scans interrupted, without new network operations or lost records.
- R4: Doctor reports versions, supported families, status and recommended action,
  dependency imports/versions, permissions, worker fallback discovery, workspace
  and optional wordlist checks. It never installs tools.
- R5: existing workspace/DB permissions are tightened before use; DB and WAL/SHM
  symlinks are rejected. Schema 3 prevents older releases opening new error-kind
  records. Project/history lookup indexes are added; versions 1/2 migrate.
- R6: invalid DNS import rows cannot contribute partial records; family/type and
  canonical name/address values are validated before any row is accepted.
- R7: arbitrary HTTP exception payloads are omitted from persisted warnings;
  structured errors distinguish blocked scope, tool missing/failure, timeout,
  permission, resource/cancellation, parser and network/I/O failures. NVD uses
  centralized bounded HTTP. Provider credentials remain environment-only.
- D1: Python >=3.12 is consistent across metadata, installer, package and docs;
  Kali/Parrot are the primary distribution targets.
- D2: graph directions, bounded arrows and click-to-observation/evidence details
  are present. Strings are escaped; the details panel uses textContent.
- D3: GUI details use the full row object, preserved through table sorting.
- Additional verified API corrections: Swagger basePath, inherited parameters,
  null MX records and operation-level security overrides are handled explicitly.
  Lifecycle UNKNOWN, known EOL and potential CVE conditions remain distinct.

### Partial and remaining issues

P1 is partly resolved: native HTTP DNS now has a five-second caller deadline and
four global resolution slots, with scope reloaded before connecting. A stuck
libc call cannot be forcibly cancelled, but further calls fail closed when the
bounded pool is full. Go/external jobs use a policy snapshot plus cancellation;
CLI processes must be stopped before policy replacement/recovery. Native DNS is
still serial; no pause/resume or automatic retry/backoff is implemented.

P2 is partly resolved: Doctor and report/graph generation now use GUI background
workers; repeated report/graph tasks are bounded to one per window. Large table
refresh/snapshot loading still happens synchronously. The offline 1,150-record
cProfile fixture measured persistence 0.421s, JSON finish 0.030s, snapshot 0.011s,
and reports 6.746s; PDF layout dominated (4.809s). These are instrumented single
runs on this machine, not throughput guarantees. No additional compiled worker
or speculative optimization was introduced.

Remaining baseline unresolved findings: CRITICAL 0, HIGH 0, MEDIUM 2 (partial
P1/P2), LOW 0. Broader missing/release features listed above are not silently
marked complete. Version-family matching is not full compatibility certification.
Global cross-process scan scheduling, live external-engine/paid-provider tests,
UDP qualification, vendor/backport applicability, production identity/license,
signing trust root and public APT hosting remain release work.

### Validation results

Environment: existing Kali GNU/Linux Rolling 2026.3, Python 3.14.7 virtual
environment. No third-party active targets were contacted.

- Full Python suite: 367 run, 367 passed, 0 failed, 0 skipped.
- Go: three tests passed with race detection; go vet passed; worker build passed.
- CLI: version/help passed. Doctor: parsed JSON, Python/core dependencies READY,
  bundled worker READY; unavailable/broken optional tools remain clearly visible.
- GUI: offscreen startup/event-loop shutdown passed; table/workflow GUI tests passed.
  A real graphical desktop session has not been qualified.
- Database: creation, v1-to-v3 migration, future-schema rejection, unique merges,
  foreign-key enforcement, rollback, concurrent reads/writes, integrity checks,
  KeyboardInterrupt and explicit hard-interruption recovery tested.
- Loopback TLS/Nmap: COMPLETE, four HTTP responses, one real open port, two API
  observations, one JavaScript file; verified certificate/TLS metadata; reports
  generated. Scan 09d50474-8477-4b1e-92da-cb7bedb12fc3 used only the script's own
  transient 127.0.0.1 listener.
- JSON/CSV/HTML/PDF/directed graph exports passed, including escaping and evidence
  directory protection regressions.
- Debian 0.2.0-2 built; staging imports/entry points/worker version, DB creation,
  payload overlay and staged removal preserve user data. These are staging
  checks, not actual apt lifecycle validation.
- Local development APT metadata signed and verified using a temporary discarded
  key. Nothing published; host package configuration unchanged.
- Static checks: compileall, bash -n, go vet, git diff --check passed. No Python
  lint configuration or coverage instrumentation is installed; coverage percentage
  is unavailable. pip check reported no broken requirements.
- A manual Kali/Parrot container qualification workflow now checks source tests,
  prior-package install/current upgrade, installed CLI/GUI/database and actual
  remove/purge. It is NOT RUN here: Docker/Podman are unavailable. Clean Parrot,
  clean Kali installation and full desktop VM lifecycle remain NOT TESTED.

Next phase: execute supported-distribution release qualification, resolve any
actual dependency/GUI/lifecycle failures, then finalize license/maintainer and
operator-managed signed repository before public production claims.

## Architecture follow-up against c1d08eb

See [ARCHITECTURE_AUDIT.md](ARCHITECTURE_AUDIT.md) for dependency boundaries,
source-verified stage status and seven additional verified findings (0 CRITICAL,
0 HIGH, 3 MEDIUM, 4 LOW), now fixed and regression-tested. Current validation:
386 Python tests passed, 0 failed/skipped; offscreen GUI, primary module entry,
Doctor, loopback TLS/real Nmap/reports and Debian 0.2.0-3 staging passed. Existing
partial DNS snapshot and large GUI refresh limitations remain. Clean distro apt
lifecycle/desktop qualification is still unvalidated; an isolated overlay mount
attempt failed, and no host package configuration was changed. Earlier test
counts and package revisions above are historical results of the preceding audit.

## Release qualification follow-up

See [RELEASE_QUALIFICATION.md](RELEASE_QUALIFICATION.md) for source-verified
version/dependency policy, exact official image digests and real package
lifecycle results. Qualification found and fixed missing Debian NumPy,
overstrict distro NetworkX/Plotly minima, and leftover package bytecode on
removal. Debian is now 0.2.0-4; Python remains >=3.12. CyberIntel is retained.
The full source suite passed 391 tests; distro CyberRecon subsets each passed
127 with one intentional disposable-host guard skip. Installed CLI/Doctor,
offscreen GUI, own-loopback TLS/Nmap/reports, upgrade/data preservation and
separate remove/purge/reinstall passed in disposable Kali and Parrot roots.
Namespace UID 1000 default-home/GUI checks passed. Actual desktop VMs, real
multi-user/root-owned host lifecycle, licensing and public APT remain gates.
