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

Projects require an authorization reference. Exclusions override inclusions, including excluded public IPs returned by DNS. Wildcards include descendants, not their apex for active requests. Scope rules accept domains, IPs and CIDRs; URLs belong in the target field and are rejected as rules rather than silently broadened to whole domains. Private destinations require separate explicit IP authorization. Native HTTP pins resolved addresses, verifies TLS, blocks out-of-scope and TLS downgrade redirects, does not inherit proxies, limits encoded/decoded response size and total requests, and stores parameter names without values. TXT values, cookie values, CSP nonces and digest challenge values are not persisted. Changing scope affects subsequent native requests. Desktop scope editing cancels the current job and records policy history; schema-1 workspaces migrate automatically to schema 2.

For an authorized lab with a private certificate authority, use `--ca-bundle trusted-ca.pem` or the desktop CA field. Certificates and hostnames remain verified. The scan records the public CA bundle hash rather than its contents. HTTPS observations include negotiated TLS and certificate validity/hash metadata when supplied by the transport.

The desktop browser supports project creation, scope inspection, bounded native scans, cancellation, sortable/filterable observation tables, scan history, comparison, an offline interactive graph and JSON/CSV/HTML/PDF reports. Native collection covers DNS records, HTTP observations, technology banners, links, API candidates, JavaScript hashes, source-map/endpoint candidates, redacted sensitive-assignment counts, and attributed relationships. HTTP configuration findings are review items, not confirmed vulnerabilities. Historical URLs and certificate names remain labelled historical until independently checked. A missing observation in comparison is not proof of removal. Graphs display up to 300 nodes; tables show up to 1,000 rows; JSON exports preserve all stored observations.

`--wordlist paths.txt` adds up to 200 relative content paths to the native pinned request queue, subject to the 30-page and 100-request budgets. A randomized negative control identifies identical wildcard responses for review. A successful response may be a soft-404 or authentication page; it does not establish content exposure. Scan comparisons ignore control URLs, collection timestamps and per-scan raw evidence paths.

`--lifecycle` requests upstream release-cycle metadata from [endoflife.date](https://endoflife.date/docs/api/v1/). Unknown products/versions remain UNKNOWN. `NOT_EOL` is upstream cycle metadata, not a guarantee of security or installed-package support. `--cve` sends up to three observed versioned CPEs to the [NVD API](https://nvd.nist.gov/developers/vulnerabilities), retaining source, timestamps, reason and next steps. Results stay unconfirmed candidates; vendor advisories, configurations and backports require verification. No CVE match does not establish safety.

`--go-dns` uses the bounded Go A/AAAA worker. Build it using [the worker instructions](workers/README.md), which document the Python/Go interface and scope snapshot limitations. Go is optional at runtime with the native Python resolver.

SQLite and per-scan JSON are stored under `~/.local/share/cyberrecon`; override with `CYBERRECON_HOME` or `--home`. Each scan records settings, scope, warnings and status. Failed optional engines produce a failed/partial result rather than invented successes.

Host intelligence reads existing [Shodan](https://developer.shodan.io/api) or [Censys Platform](https://docs.censys.com/reference/v3-globaldata-asset-host) observations for an explicitly scoped public IP. Set `SHODAN_API_KEY`, or `CENSYS_PLATFORM_TOKEN` and optional `CENSYS_ORGANIZATION_ID`, in the launch environment. The desktop Host intelligence button uses the same connectors. Keys are not stored in the workspace; contact/location/WHOIS payloads are discarded. Service metadata stays labelled historical/unverified and no provider rescan is requested. Queries may consume account credits. These connectors have mock-transport tests; paid live access was not exercised.

CLI adapters exist for certificate transparency (crt.sh/Cert Spotter fallback), passive Subfinder/Assetfinder/Amass v3, historical gau/waybackurls and explicit-IP Nmap TCP/UDP. UDP requires appropriate privileges; the application does not elevate itself. Fixed-command WhatWeb and ffuf functions are implemented but are not wired into the scan workflow; their engine-owned DNS handling is not equivalent to the native pinned transport. JSONL imports are implemented for dnsx, ProjectDiscovery httpx, Naabu and Katana. Imports are scope filtered, bounded and explicitly labelled unverified; arbitrary engine response bodies and headers are discarded. Gobuster is a future integration. Doctor checks PATH presence, not engine version compatibility.

OpenAPI/Swagger response parsing extracts bounded endpoint/method/parameter/security metadata without retaining examples or invoking documented mutation methods. GraphQL discovery identifies candidate paths; introspection and authenticated assessment are not implemented. Remaining specification work includes full engine orchestration/version compatibility tests, advanced schema parsing and content calibration, authenticated API assessment, vendor-specific/backport-aware CVE intelligence, resumable scheduling, and distribution release validation. Existing CyberIntel metadata retains Python 3.11 compatibility; the new Debian package requires Python 3.12.

## Debian and signed APT artifacts

```sh
python scripts/build-cyberrecon-deb.py
python scripts/build-cyberrecon-deb.py --worker dist/cyberrecon-dns
python scripts/build-cyberrecon-apt.py dist/cyberrecon_0.2.0-1_amd64.deb --output dist/apt --sign-key OPERATOR_SIGNING_KEY_FINGERPRINT
```

Without a Go worker the package architecture is `all`; with a worker it is the build host's architecture. Build the Go binary for that architecture. Dependencies use distribution packages and Python 3.12+, with no automatic pip installation in maintainer scripts. The launcher works independently of the current directory. Standard installation/update/uninstall is `sudo apt install ./cyberrecon_VERSION_ARCH.deb` / `sudo apt remove cyberrecon`; user-owned workspaces are preserved.

For local signing tests only, replace `--sign-key` with `--development-key` and choose a new empty output directory. The temporary private key is discarded; the repository includes its public key and fingerprint. This is **not a production trust root**. Operator keys must persist securely to sign future updates. Build scripts create local artifacts; they never publish or change host APT configuration.

APT metadata expires after seven days and must be regenerated and re-signed for continued use. The development signing key expires sooner; it is only for artifact verification.

`python scripts/verify_cyberrecon_lab.py --tls` starts an ephemeral loopback TLS service, verifies native discovery/certificate metadata, scans that script-owned port with real Nmap when available, and generates reports under ignored `artifacts/`. Its temporary certificate key is discarded. No external targets are contacted. CI runs the Go race tests and this local TLS/Nmap check.

Kali/Parrot installation, upgrades and uninstall still require validation on fresh supported installations. A `.deb` and signed local development repository have been built here, but neither distribution installation is validated. Operator identity, project license and public hosting must be finalized before redistribution. Dependencies may differ across Parrot releases.
