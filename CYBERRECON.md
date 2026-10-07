# CyberRecon 0.2.0 — development implementation

CyberRecon is a separate entry point in this repository. Existing CyberIntel workspaces and commands remain available. This is an initial implementation of the supplied specification, **not a completed production release**.

For Kali and Parrot development work, use Python 3.12+ in a virtual environment. Install with `python -m pip install -e .`, then run `cyberrecon`. CLI usage also works without reinstalling: `python -m cyberrecon.cli --help`.

```sh
cyberrecon --doctor
cyberrecon project "Authorized lab" --include example.org --include '*.example.org' --exclude excluded.example.org --authority 'Program scope URL or written permission reference'
cyberrecon projects
cyberrecon scan example.org --project PROJECT_ID --crawl
cyberrecon scans PROJECT_ID
cyberrecon compare BEFORE_SCAN_ID AFTER_SCAN_ID
cyberrecon export SCAN_ID ./export
cyberrecon scope-import PROJECT_ID scope.json
cyberrecon import-engine httpx authorized-results.jsonl --project PROJECT_ID --target example.org
cyberrecon scan example.org --project PROJECT_ID --passive ct --crawl --lifecycle --go-dns
cyberrecon host-intel shodan AUTHORIZED_PUBLIC_IP --project PROJECT_ID
```

Projects require an authorization reference. Exclusions override inclusions, including excluded public IPs returned by DNS. Wildcards include descendants, not their apex for active requests. Scope rules accept domains, IPs and CIDRs; URLs belong in the target field and are rejected as rules rather than silently broadened to whole domains. Private destinations require separate explicit IP authorization. Native HTTP pins resolved addresses, verifies TLS, blocks out-of-scope and TLS downgrade redirects, does not inherit proxies, limits encoded/decoded response size and total requests, and stores parameter names without values. TXT values, cookie values, CSP nonces and digest challenge values are not persisted. Changing scope affects subsequent native requests. Desktop scope editing cancels the current job and records policy history; schema-1/2 workspaces migrate automatically to schema 3; older releases reject the newer schema.

For an authorized lab with a private certificate authority, use `--ca-bundle trusted-ca.pem` or the desktop CA field. Certificates and hostnames remain verified. The scan records the public CA bundle hash rather than its contents. HTTPS observations include negotiated TLS and certificate validity/hash metadata when supplied by the transport.

The desktop browser starts scans directly from target, inline allowed/excluded scope and an authorization reference. Blank allowed scope authorizes only the exact entered target. Internal history contexts are saved/reused automatically; there is no New project dialog. Saved scopes / history can be selected to reopen earlier scans. It also supports scope inspection, bounded native scans, cancellation, sortable/filterable observation tables, scan history, comparison, an offline interactive graph and JSON/CSV/HTML/PDF reports. Native collection covers DNS records, HTTP observations, technology banners, links, API candidates, JavaScript hashes, source-map/endpoint candidates, redacted sensitive-assignment counts, and attributed relationships. HTTP configuration findings are review items, not confirmed vulnerabilities. Historical URLs and certificate names remain labelled historical until independently checked. A missing observation in comparison is not proof of removal. Directed graphs display up to 300 nodes, with click-to-observation/evidence details and up to 600 direction arrows; tables show up to 1,000 rows; JSON exports preserve all stored observations.

`--wordlist paths.txt` adds up to 200 relative content paths to the native pinned request queue, subject to the 30-page and 100-request budgets. A randomized negative control identifies identical wildcard responses for review. A successful response may be a soft-404 or authentication page; it does not establish content exposure. Scan comparisons ignore control URLs, collection timestamps and per-scan raw evidence paths.

`--lifecycle` requests upstream release-cycle metadata from [endoflife.date](https://endoflife.date/docs/api/v1/). Unknown products/versions remain UNKNOWN. `NOT_EOL` is upstream cycle metadata, not a guarantee of security or installed-package support. `--cve` sends up to three observed versioned CPEs to the [NVD API](https://nvd.nist.gov/developers/vulnerabilities), retaining source, timestamps, reason and next steps. Results stay unconfirmed candidates; vendor advisories, configurations and backports require verification. No CVE match does not establish safety.

`--go-dns` uses the bounded Go A/AAAA worker. Build it using [the worker instructions](workers/README.md), which document the Python/Go interface and scope snapshot limitations. Go is optional at runtime with the native Python resolver.

SQLite and per-scan JSON are stored under `~/.local/share/cyberrecon`; override with `CYBERRECON_HOME` or `--home`. Each scan records settings, scope, warnings and status. Failed optional engines produce a failed/partial result rather than invented successes.

Host intelligence reads existing [Shodan](https://developer.shodan.io/api) or [Censys Platform](https://docs.censys.com/reference/v3-globaldata-asset-host) observations for an explicitly scoped public IP. Set `SHODAN_API_KEY`, or `CENSYS_PLATFORM_TOKEN` and optional `CENSYS_ORGANIZATION_ID`, in the launch environment. The desktop Host intelligence button uses the same connectors. Keys are not stored in the workspace; contact/location/WHOIS payloads are discarded. Service metadata stays labelled historical/unverified and no provider rescan is requested. Queries may consume account credits. These connectors have mock-transport tests; paid live access was not exercised.

CLI adapters exist for certificate transparency (crt.sh/Cert Spotter fallback), passive Subfinder/Assetfinder/Amass v3, historical gau/waybackurls and explicit-IP Nmap TCP/UDP. UDP requires appropriate privileges; the application does not elevate itself. The standalone WhatWeb and ffuf adapter interfaces now use safe native HTTP collection instead of external execution, because tool-owned DNS bypassed resolved-IP exclusions. Native banner/content collection is already wired into the workflow; external tool execution stays disabled. Amass enumeration requires a successfully probed v3 version. Nmap is constrained to two packets/second and two parallel probes; service-detection timings are engine-controlled. JSONL imports are implemented for dnsx, ProjectDiscovery httpx, Naabu and Katana. Imports are scope filtered, bounded and explicitly labelled unverified; arbitrary engine response bodies and headers are discarded. Gobuster is a future integration. Doctor probes executable versions with a three-second/64-KiB bound, reports supported CLI families, missing/broken/unsupported tools, Python dependencies, workspace permissions and an optional wordlist. READY is a CLI family match, not comprehensive compatibility certification. Version-less Assetfinder/waybackurls require manual review. No tools are installed by Doctor.

OpenAPI/Swagger response parsing extracts bounded endpoint/method/parameter/security metadata without retaining examples or invoking documented mutation methods. GraphQL discovery identifies candidate paths; introspection and authenticated assessment are not implemented. Remaining specification work includes full engine orchestration/version compatibility tests, advanced schema parsing and content calibration, authenticated API assessment, vendor-specific/backport-aware CVE intelligence, resumable scheduling, and distribution release validation. Both project metadata and Debian packaging now require Python 3.12+.

## Debian and signed APT artifacts

```sh
python scripts/build-cyberrecon-deb.py
python scripts/build-cyberrecon-deb.py --worker dist/cyberrecon-dns
python scripts/build-cyberrecon-apt.py dist/cyberrecon_0.2.0-5_amd64.deb --output dist/apt --sign-key OPERATOR_SIGNING_KEY_FINGERPRINT
```

Without a Go worker the package architecture is `all`; with a worker it is the build host's architecture. Build the Go binary for that architecture. Dependencies use distribution packages and Python 3.12+, with no automatic pip installation in maintainer scripts. The removal/upgrade hook uses Debian `py3clean -p cyberrecon` to clean package bytecode; it never touches user workspaces. The launcher works independently of the current directory. Standard installation/update/uninstall is `sudo apt install ./cyberrecon_VERSION_ARCH.deb` / `sudo apt remove cyberrecon`; user-owned workspaces are preserved.

For local signing tests only, replace `--sign-key` with `--development-key` and choose a new empty output directory. The temporary private key is discarded; the repository includes its public key and fingerprint. This is **not a production trust root**. Operator keys must persist securely to sign future updates. Build scripts create local artifacts; they never publish or change host APT configuration.

APT metadata expires after seven days and must be regenerated and re-signed for continued use. The development signing key expires sooner; it is only for artifact verification.

`python scripts/verify_cyberrecon_lab.py --tls` starts an ephemeral loopback TLS service, verifies native discovery/certificate metadata, scans that script-owned port with real Nmap when available, and generates reports under ignored `artifacts/`. Its temporary certificate key is discarded. No external targets are contacted. CI runs the Go race tests and this local TLS/Nmap check.

See [release qualification](docs/RELEASE_QUALIFICATION.md) for measured Kali/Parrot package lifecycle checks and exact image digests. These checks do not certify a graphical desktop VM or a production APT repository. MIT is selected. Operator identity and public hosting remain release blockers.

The clean-image path qualified locally uses `--no-install-recommends` for APT
dependency resolution. Default recommendations pull additional system packages
that exceed the local single-UID namespace; that path still needs a privileged
container/VM check. Nmap can be installed separately for explicit-IP port scans.

## Audit hardening and recovery

See [the full audit](docs/AUDIT.md) and [canonical observation contracts](docs/SCHEMAS.md).
Credentialled redirects cannot cross origins (including ports). DNS resolution
has a five-second deadline with at most four daemon resolver calls in flight;
a stuck libc resolver consumes one slot until it returns, and further requests
fail closed when capacity is exhausted. Cancellation does not forcibly kill
libc threads. Managed scan/evidence directories and database sidecars reject
symlinks; existing workspace permissions are tightened before opening SQLite.
Native HTTP is serial per workflow; DNS and optional tools have independent
bounded budgets. No automatic native retries or pause/resume are implemented.

Observations preserve stable IDs, first/last timestamps and all contributing
sources within each scan. CURRENT means collected now, not confirmed vulnerable;
imported and provider observations have separate confidence/status labels.
Lifecycle UNKNOWN stays unknown. Known upstream EOL and potential CVE matches
remain distinct conditions requiring installed-package and backport validation.
Structured errors retain safe categories without arbitrary exception payloads.
The desktop runs Doctor, reports and graph generation in background workers.

After stopping all scan processes for a project, recover hard-interrupted scans:

```sh
cyberrecon recover PROJECT_ID
cyberrecon --doctor --doctor-wordlist ./paths.txt
python scripts/verify_cyberrecon_startup.py
python scripts/verify_cyberrecon_package.py dist/cyberrecon_0.2.0-5_all.deb
python scripts/profile_cyberrecon.py
```

Recovery is explicit and does not resume network operations. Do not recover a
project while another process is scanning it. Ctrl-C marks the current native
scan cancelled and preserves collected data. Hard crashes are handled using
SQLite/WAL plus explicit recovery; comparisons must consider interrupted status.

Package staging tests validate payload imports, fixed launcher metadata,
database creation and preservation under extraction/overlay/staged removal.
They do not replace actual apt install/upgrade/remove tests. The manually
triggered `Kali and Parrot release qualification` workflow uses official
[Kali containers](https://www.kali.org/docs/containers/official-kalilinux-docker-images/)
and [Parrot containers](https://www.parrotsec.org/docs/containers/parrot-on-docker/),
runs tests and checks actual prior-package upgrade/removal in disposable
containers with captured failure evidence. The workflow itself has not been run here; local disposable-root results are documented separately. Desktop/session and
privilege behavior still require supported-OS VM testing before a public release.
Do not configure unsigned repositories or use `curl | bash`. Public
`apt install cyberrecon` remains unavailable until a signed repository is hosted.

## Architecture follow-up

[Architecture audit](docs/ARCHITECTURE_AUDIT.md) records the primary CyberRecon
pipeline and the required shared CyberIntel dependency; the compatibility GUI,
launcher and its independent database remain intact. `python -m cyberrecon` is
the primary module entry point. Debian revision 0.2.0-3 includes these fixes.
New URL observations normalize IDNs, trailing dots, IP spellings and default
ports; stored historical keys are retained, so comparisons across this update
may reflect collector normalization changes rather than asset removal. Nmap
service technologies are now connected to the directed graph.

Doctor includes executable paths/minimum versions and read-only basic database
path/header checks. HEADER_VALID is not an integrity check or schema migration
verification. Missing optional tools are still reported without installation.
NVD processing isolates malformed entries and retains bounded advisory CVSS
evidence; scores do not establish target applicability or override backport
uncertainty. Paid providers and external-engine compatibility still require
separate qualification.

## Release qualification follow-up

Debian revision 0.2.0-4 adds the required NumPy graph dependency, aligns tested
NetworkX >=3.2.1 and Plotly >=5.20 support with distro packages, and cleans
package bytecode on removal/upgrade. Python remains >=3.12. Doctor now checks
NumPy and dependency patch versions. See [release qualification](docs/RELEASE_QUALIFICATION.md)
for supported/tested versions, real lifecycle evidence, and remaining gates.


## Production release preparation

The Debian 0.2.0-5 candidate retains CyberRecon 0.2.0 and CyberIntel compatibility.
MIT is selected; public maintainer identity and HTTPS APT hosting remain unavailable.
See [production readiness](docs/PRODUCTION_RELEASE_READINESS.md),
[release checklist](docs/RELEASE_CHECKLIST.md), [APT/signing operations](docs/APT_REPOSITORY.md),
and [compatibility migration plan](docs/COMPATIBILITY_MIGRATION.md).
Desktop VM, reboot and production publication gates remain blocked or untested.
