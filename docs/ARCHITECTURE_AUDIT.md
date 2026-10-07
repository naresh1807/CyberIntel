# Current architecture audit

Baseline: c1d08eb. This document describes source-verified behavior, not a
production certification. Both applications remain working; no second scanner
or database architecture is introduced.

## Product and dependency boundaries

CyberRecon is the primary bug-bounty reconnaissance product: cli -> gui/scanner
-> Scope/ScopedHTTP/engines -> Repository -> intelligence/reports/graph.
CyberIntel is a maintained compatibility desktop for cases, authorized offline
forensics and public-provider collection. It is also a required shared library.
CyberRecon imports five shared modules: models (errors/time), output (atomic
exports), connectors (domain validation and CT collection), nmap_scan (fixed
argv/XML parsing) and web_assessment (header review). Debian copies these plus
package __init__; it does not include or expose the CyberIntel GUI.

There is one Python distribution metadata file, pyproject.toml, named
cyberintel-suite version 0.1.0 for compatibility. The CyberRecon application and
Go protocol report 0.2.0; Debian now uses 0.2.0-4 (see release qualification). These are different version layers,
not duplicate distributions. Renaming the distribution requires an explicit
migration/release plan. The two console commands have distinct names and do not
conflict: cyberrecon -> cyberrecon.cli; cyberintel -> cyberintel.app. launcher.py
and scripts/package-linux.sh intentionally remain CyberIntel compatibility paths.
CyberRecon is launched with its console command or module entry point.

## Persistence/configuration duplication

CyberRecon: ~/.local/share/cyberrecon, schema 3, projects as internal authorized
history contexts, scans, observations and scope history. GUI scans create/reuse
contexts automatically; no separate New project step is required.
CyberIntel: ~/.local/share/cyberintel, separate SQLite cases/evidence/cache/audit,
config.json and local credentials/vault support. Neither database may be merged
or deleted as cleanup: they represent different data and authorization models.
CyberRecon provider keys come only from environment variables. The legacy
CyberIntel consent UI does not consume CyberRecon project policies; use the
CyberRecon entry point for project-scope-controlled reconnaissance.

## Capability and pipeline matrix

| Stage | Implementation / connection | Optional / failure / validation |
| --- | --- | --- |
| Authorization/scope | centralized Scope and Repository; CLI/GUI | required; rejects unauthorized targets before scan |
| Passive discovery | CT/Subfinder/Assetfinder/Amass v3 adapters called by scanner | opt-in; warning/partial; mock CT and version tests; live engine qualification partial |
| DNS | native seven-family DNS; optional Go A/AAAA | scoped names; bounded deadlines; Go snapshot/cancel; mock and Go race tests |
| HTTP/TLS/live hosts | pinned ScopedHTTP; saved assets/URLs/banner technologies | bounded GET/HEAD/OPTIONS; mock and script-owned loopback TLS |
| Ports/services | fixed explicit-IP Nmap TCP/UDP | opt-in; failure isolated; real loopback TCP; UDP not live-qualified |
| URLs/JS/API/content | native crawler, JS/static patterns, OpenAPI/Swagger, native wordlist paths | crawl/content opt-in; no mutation testing; bounded/mock/loopback tests |
| History | gau/waybackurls selected adapter | opt-in, sanitized, historical; live engine compatibility not qualified |
| Normalization/correlation | canonical DNS/URL facts, unique observations, typed relationships | sources/IDs/timestamps/evidence retained; regression coverage |
| Lifecycle/CVE | endoflife.date/NVD through scoped provider HTTP | opt-in; candidate/EOL evidence only; vendor/backport assessment absent |
| Imports | dnsx/httpx/Naabu/Katana JSONL parsers | connected CLI import command, not active orchestration; unverified records |
| ffuf/WhatWeb | callable safe native replacement interfaces | scanner uses equivalent native content/banner stages; external execution deliberately disabled |
| Gobuster | Doctor description only | not implemented or connected |
| Reports/graph/comparison | explicit CLI/GUI export, directed graph, per-project diff | tested; missing observations never prove closed/removed assets |
| GUI | direct scan form, tabs/tables/workers/cancel/filter/details | offscreen tested; large refresh remains partly synchronous |
| Packaging | Debian and local signed development APT builders | built/staging tested; clean distro/desktop lifecycle qualification pending |

CORS analysis exists in legacy web_assessment but is not wired into CyberRecon
native HTTP findings. Advanced authenticated API/GraphQL introspection, scheduler
resume, comprehensive external-tool fixtures and backport-aware applicability
are not implemented. Raw Nmap XML is retained privately with hashes; native
HTTP bodies, cookies and credential values are intentionally not persisted.

## Verified current-phase findings before fixes

| ID | Severity | Code evidence |
| --- | --- | --- |
| A1 | MEDIUM | clean_url retains trailing-dot hosts, default ports and expanded IP spellings; imports and native URL keys diverge. |
| A2 | MEDIUM | enrich_cves has no per-entry validation; one malformed advisory aborts subsequent entries; malformed CPE data can escape optional enrichment handling. |
| A3 | MEDIUM | Doctor workspace check only tests directory writability, missing unsafe DB sidecars/invalid database files. |
| A4 | LOW | Nmap technologies saved without service->technology relationship, disconnecting them from graph. |
| A5 | LOW | Doctor result lacks executable path and explicit minimum-version fields. |
| A6 | LOW | URL scope accepts port zero and clean_url accepts DEL path controls despite documented malformed/control rejection. |
| A7 | LOW | CVE observations discard available advisory CVSS evidence. |

Critical 0, High 0, Medium 3, Low 4. Previously documented residual DNS snapshot,
large GUI refresh and production release limitations remain applicable; these
counts concern new verified findings against c1d08eb.

## Safe cleanup direction

Keep cyberintel installed and its entry point/data intact. Incrementally extract
shared utilities into CyberRecon only after dedicated parity tests and package
staging verification. Update imports and Debian payload together, then consider
separating the legacy desktop into an optional distribution. Do not delete the
compatibility package while these imports exist. Preserve current scope and
SQLite designs; qualification, not a rewrite, is the next release gate.

## Current-phase validation

Recorded after remediation below.

### Remediation and measured validation

A1–A7 are fixed with regressions: new URLs share canonical IDN/host/IP/default
port spelling; NVD malformed records and CPEs no longer abort valid candidates;
Doctor includes paths/minimums and non-mutating DB sidecar/type/header checks;
Nmap service technologies have graph edges; port zero and DEL URLs reject;
bounded advisory CVSS evidence is retained without confirming applicability.
Broken dependency reports preserve installation/version information.
`python -m cyberrecon` is tested alongside the existing CLI entry point. No
CyberIntel functionality, entry point, configuration or user data was removed.

Full Python suite: 386 passed, 0 failed, 0 skipped (35.03s). Coverage percentage
is unavailable: no coverage instrumentation is installed. compileall, bash -n
and git diff --check passed; no Python linter/type-check configuration exists.
Go was unchanged in this phase; its existing race suite is separately validated.
CLI version/help and Doctor JSON passed on existing Kali 2026.3/Python 3.14.7;
core dependencies READY, executable paths present. GUI startup/event-loop exit
passed offscreen. Real script-owned loopback TLS/Nmap scan completed: four HTTP
responses, one real open port, two APIs, one JS file, JSON/CSV/HTML/PDF/graph
reports. Scan ID bdc4ea5e-f522-41f4-baa2-cb4540237b40.

Debian 0.2.0-3 built; staged primary module entry points, optional worker version,
DB creation, overlay/reinstall payload and staged removal preservation passed.
These are staging checks, not real apt installation/uninstallation. Rootless
read-only namespaces are available outside the execution sandbox, but a private
writable overlay required for an isolated apt test fails with kernel/mount
`Invalid argument`. Docker/Podman/bootstrap tools are absent. No host apt
installation or package configuration change was performed. Clean Kali, Parrot
and graphical desktop release qualification remain NOT TESTED. The manual
container workflow now upgrades the actual previous c1d08eb Debian revision 2
to current revision 3; it has not been run here.

Remaining known limitations include two partial MEDIUM findings from the prior
audit: snapshot/cancellation semantics for external/Go jobs and synchronous large
GUI refresh. CORS/authenticated API analysis, active import-tool orchestration,
full external/paid-provider qualification, backport-aware CVE applicability,
resume scheduling, license/maintainer identity and production APT hosting remain
incomplete. READY means a supported CLI family, not fully qualified integration.
Next phase: run the prepared distribution qualification and real desktop VM
checks; fix measured failures before extracting shared compatibility utilities.

## Release qualification follow-up

[RELEASE_QUALIFICATION.md](RELEASE_QUALIFICATION.md) supersedes the earlier
NOT TESTED package lifecycle status with actual disposable official-image
Kali/Parrot results, without claiming a desktop VM certification. Revision 4
fixes measured dependency and bytecode-removal failures; no shared utility
extraction, compatibility deletion or pipeline rewrite was performed.
