# CyberIntel Suite

A modular Python desktop application for public intelligence collection and authorized offline forensic analysis. The PySide6 interface uses a dark purple, blue and charcoal palette with case selection, sortable/filterable tables, background jobs and PyQtGraph charts. No fixture data is loaded into a user's workspace automatically.

This is version **0.1.0**, a tested development release, not a claim of production certification. All pages invoke implemented services. Credential-dependent providers and external tools report errors when unavailable; they never substitute synthetic results.

## Run on this Windows workspace

The dependencies have already been installed in `.venv`:

```powershell
.\.venv\Scripts\python.exe -m cyberintel
```

The app opens directly into the local workspace, with no login or registration. Although Linux is the deployment target, the desktop and tabular analysis also run on Windows. TShark must be installed separately for PCAP analysis.

## Kali Linux / Ubuntu installation

Use Python 3.11 or newer; Ubuntu 24.04+ and current Kali installations are the intended targets. Run as a regular desktop user, not root.

```bash
bash scripts/install-linux.sh
.venv/bin/python -m cyberintel
```

The script installs system libraries and TShark through apt, creates a virtual environment, and installs the application. When the TShark installer asks whether non-superusers may capture packets, offline analysis does not require capture privileges. Manual equivalent:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip libegl1 libopengl0 \
  libxcb-cursor0 libxkbcommon-x11-0 libxcb-icccm4 libxcb-keysyms1 \
  libxcb-shape0 libxcb-xinerama0 tshark
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m cyberintel
```

If an older Ubuntu installation has Python 3.10, use an OS-supported Python 3.11+ installation or upgrade the OS before creating the virtual environment.

## Implemented workflow

1. Create a case with scope and authority notes. Select it in the top-right selector.
2. Collect public DNS, RDAP, certificate transparency or website metadata. Use **Subdomain discovery** for a dedicated searchable list, optional DNS checks and CSV export. RDAP provides registration information; legacy port-43 WHOIS is not implemented. CT discovery is passive and does not scan hosts. A website metadata request requires the authorization checkbox.
3. Use the public HIBP breach catalog without credentials. Exposure checks require your own authorized HIBP key/subscription; domain exposure also requires provider-side domain verification. Domain results are reduced to breach counts: returned email aliases are not persisted. Configure credentials under Settings.
4. Enrich IPs, domains or URLs through URLhaus or OTX. The application sends indicators to providers; it never visits malicious indicator URLs or requests payload downloads. URLhaus recent metadata can refresh every 15 minutes while the application is open.
5. Attach authorized CSV/XLSX, PCAP/PCAPNG or other supported evidence. Set source, timezone-aware acquisition time and provenance kind. The application copies the file into its evidence store and hashes the copy. Original files are never modified.
6. Analyze attached CDR, packet captures or location/tower files. All results are automatically saved under the case. A hash mismatch refuses analysis. Reopen saved analyses from Reports & audit to regenerate maps or relationship graphs.
7. Export a case PDF/CSV with source references, collection timestamps, evidence inventory and integrity checks. CSV cells receive formula-injection protection. Graphs and maps are generated as separate interactive HTML files.

Collections made without an active case can be viewed and cached, but are not saved as case findings. A case is required for offline analysis, evidence management, reports and monitors.

### Data status

| Status | Meaning |
| --- | --- |
| Live | Returned by the provider during this collection |
| Cached / fresh | Stored successful response younger than the configured TTL |
| Cached / stale | An older response, or fallback after a failed refresh; original timestamp retained |
| Unavailable | Provider denied access, configuration is missing, or collection failed; no success implied |
| Offline | Analysis of an imported local file |
| Synthetic | Analysis of explicitly labeled test evidence |

Historical live findings become cached when restored to a module. Saved report status describes the original collection; the timestamp is always included. Historical observations do not prove present-day activity or safety.

### Breach monitoring

Select authorized email/domain exposure, enter the target, confirm authorization and add a watch. Watches are persisted per case, can be inspected or removed, and can be checked manually. Enable monitoring to check active-case watches every 15 minutes while the application is open. A dialog reports newly observed breach names compared with the most recent successful finding. The first successful check establishes a baseline. It does not send email or run after the application closes. Limit: 25 watches per case. Provider subscription terms govern usage; keep domain watches small and prefer manual checks when no new breach has been announced.

### Severity rules

URLhaus reports **high** when an entry is online and labeled `malware_download`, **medium** for a historical association, and **unknown** without a match. OTX uses **medium** for community pulse associations and **unknown** otherwise; pulse references are not a verified maliciousness verdict. Network heuristics flag review when a source has more than 100 initial TCP SYN packets or a DNS name exceeds 100 characters. Every result includes the rule/rationale. These rules are intentionally transparent and do not replace analyst review.

## Subdomain discovery

Open **Subdomain discovery**, enter a root domain such as `example.com`, and click **Find subdomains**. This queries crt.sh using the existing HTTPS, retry and cache controls. The crt.sh request uses one attempt with an eight-second maximum per HTTP timeout phase, rather than waiting through three retries. If crt.sh fails, the app sends the domain to the configured Cert Spotter endpoint as a fallback. The public fallback is rate limited and searches unexpired certificate issuances; its coverage differs from crt.sh. Fallback requests are capped at five pages. Pagination failures and limits retain observed names with an explicit partial-results warning. The source, original crt.sh error, and fallback warnings appear in details. If both providers fail, a saved response is labeled stale or the result is unavailable. Results are deduplicated, normalized, restricted to descendants of the domain, and exclude the apex. Wildcard-only certificate patterns are listed separately in the details pane; a wildcard certificate does not invent a concrete host.

**Resolve IPs (first 100)** is enabled by default: discovery displays observed names first, then checks A/AAAA records for up to 100 names in the background and saves the final enriched result. Uncheck it for passive CT-only discovery. The CT option in Live OSINT also enriches the first 100 names. IPv4/IPv6 columns appear beside the hostname and show readable addresses or `No A record`, `No AAAA record`, `DNS lookup failed`, or `Not checked`. IPv6 is not published for every host.

Filter/sort the table, then use **Check DNS for filtered names (max 100)** to refresh addresses or check remaining names in larger discoveries. Verification uses eight workers and a three-second lifetime per A/AAAA query, with no DNS search-suffix expansion. Rows retain independent family status, verification time, resolver attribution, and overall resolved/NXDOMAIN/no-address/error status. Timeouts remain errors, not claims that a name is absent. DNS checks do not contact websites or prove host activity. Wildcard DNS can also cause a name to resolve. DNS checks run in background workers; slow or failing resolvers can take time to complete a full batch.

**Export filtered CSV** writes visible names and their provenance/DNS fields. Discovery and verification findings are saved when a case is selected, can be restored from Reports & audit, and appear in case PDF/CSV reports. CT timestamps remain unchanged by later DNS checks. Old caches without wildcard provenance are refreshed before use. No brute-force enumeration or port scanning is performed; certificate discovery is not exhaustive. Provider outages are displayed as unavailable or a clearly labeled stale cache fallback.

Run `.venv/bin/python scripts/check_subdomains.py` for an optional public example.com check. The initial enhanced live check encountered HTTP 502 from crt.sh; see `artifacts/live-subdomain-check.json` for the latest outcome. Unit/integration checks use deterministic CT/DNS fixtures, including malformed sources, legacy caches, source failures, filtering, export and case persistence. `artifacts/subdomain-discovery-synthetic.png` is explicitly synthetic visual QA.

## Input schemas

Column names are normalized to lowercase. CSV and XLSX imports are limited to 50 MiB and 100,000 rows; expanded XLSX content is limited to 150 MiB. XLSX files with VBA content are rejected. The first worksheet is used. Phone columns are read as strings to preserve leading zeros and `+` signs.

**CDR**: `caller,callee,timestamp,duration_seconds,direction`

- Phone numbers: 3–20 digits, optional leading `+`.
- `timestamp`: ISO 8601 with `Z` or a numeric UTC offset.
- `duration_seconds`: finite, nonnegative number, at most 604800 seconds.
- `direction`: `incoming` or `outgoing`, relative to the supplied record's subscriber context. Edges always run caller → callee.

Reports include total/mean duration, call counts, unique numbers, directional counts, daily/hourly UTC frequency and weighted relationships. Plotly graphs show association edges; the relationship table provides direction and frequency. Graph rendering is limited to 2,000 edges.

**GPS/location**: `latitude,longitude,timestamp,source,record_kind`

- Coordinates must lie within valid geographic ranges.
- `record_kind`: `actual`, `inferred`, or `synthetic`. Import-level synthetic/inferred classification overrides row classifications to prevent accidental elevation to actual.
- Every row needs a source and timezone-aware timestamp.

**Cell towers**: `tower_id,latitude,longitude,source`

Tower markers describe infrastructure, not subscriber positions. Maps are limited to 10,000 records. Actual, inferred, synthetic and tower records have distinct colors. No device location is inferred from a phone number or IP address.

### Phone numbering region estimate

Open **Phone region estimate** and enter an international number beginning with `+`. For a national-format number, explicitly provide its two-letter country code, such as `IN`, `GB`, or `US`; the application does not guess the country from your computer location.

Offline `phonenumbers` metadata returns country/territory, a numbering allocation area where available, number type, original carrier, associated time zones and metadata version. The result is labeled `record_kind: inferred` and `status: offline`, and is saved as a `phone` finding when a case is selected. Saved phone findings can be restored from Reports & audit and are included in PDF/CSV reports.

These are numbering-plan associations, **not current or past device location**. Many mobile prefixes provide only a country, with no city-level area. Portability, roaming and reassignment can invalidate carrier/area associations. Number validity does not prove that it is active or identify its subscriber. The feature makes no network request, accesses no telecom database and produces no coordinates or map pin. For actual location records, import authorized GPS/tower evidence in Geospatial. [Library metadata and limitations](https://github.com/daviddrysdale/python-phonenumbers), [original-carrier portability limitation](https://daviddrysdale.github.io/python-phonenumbers/phonenumbers.carrier.html).

**PCAP**: files must have recognized PCAP/PCAPNG magic, be <=200 MiB and contain <=500,000 packets. `tshark -n -r` extracts protocol counts, byte totals, DNS queries, connection metadata and review heuristics. Processing has a 120-second timeout; DNS and connection lists show the top 5,000 entries. Split larger captures with Wireshark/editcap. Capture and traffic decryption are outside this release.

The fixtures in `examples/synthetic_*.csv` contain invented data only. Import them with source `Synthetic fixture` and data kind `synthetic` to try the workflow.

## Configuration and credentials

Default data directory: `~/.local/share/cyberintel`. Override with `--data-dir /private/path` or `CYBERINTEL_HOME`. The directory contains the SQLite database, encrypted vault, managed evidence, logs and HTML exports. Create a private workspace on an encrypted disk when working with sensitive evidence.

```bash
mkdir -p ~/.local/share/cyberintel
chmod 700 ~/.local/share/cyberintel
cp examples/config.json ~/.local/share/cyberintel/config.json
.venv/bin/python -m cyberintel --data-dir ~/.local/share/cyberintel
```

Endpoint, timeout and cache examples are in `examples/config.json`. Restart after editing configuration. Endpoint overrides must use HTTPS, port 443 and no embedded credentials; changing authenticated endpoints sends your key to the new provider, so only use trusted endpoints.

In Settings, unlock/create the vault with a separate 12+ character passphrase, enter HIBP/OTX/URLhaus keys and save. Fernet encrypts the vault using a 32-byte scrypt-derived key and a random salt. The passphrase is never written to disk. Locking removes keys from the active collector and form fields; Python does not guarantee memory zeroization. There is no vault recovery if its passphrase is lost. No API keys belong in JSON configuration or source code.

The desktop uses a single local workspace with full application permissions and no account registration or login. Existing cases and evidence remain available. Previous account records are retained for compatibility but do not restrict desktop access. Audit actions use the local-workspace actor. Protect workspace access using your operating system account and file permissions. The credential vault still requires its separate passphrase. SQLite/evidence contents are not encrypted by this application.

Linux startup uses a restrictive umask. Vault/database/log files receive private permissions. Audit entries form a SHA-256 chain, checked in Reports & audit. This detects edits to retained entries, but is not externally anchored: a privileged filesystem administrator could rewrite or truncate history. No immutable chain-of-custody certification is claimed.

HTTP collection uses TLS verification, public-address validation, pinned connections against DNS rebinding, no environment proxy inheritance, bounded responses (8 MiB), bounded retries and Retry-After handling. Authenticated cross-host redirects are rejected. Fresh cache uses a one-hour default TTL; failure fallback is explicitly stale. Logs rotate and do not log query arguments, API keys or response bodies. The database does retain authorized queries, evidence records and findings.

Folium maps use Leaflet/Javascript assets loaded from public CDNs. Base-map tiles are off by default; opt in to OpenStreetMap tiles when needed. Marker data is embedded in the local HTML and is not explicitly submitted to a geolocation service, but online assets/tiles generate browser requests. For fully disconnected maps, vendor the JavaScript/CSS dependencies; that is not included. Plotly graph HTML embeds its JavaScript.

## Architecture / project structure

```text
cyberintel/
  app.py          Entry point, authentication, private logging
  ui.py           Desktop pages, table models, background jobs, timers
  config.py       Workspace and endpoint configuration
  models.py       Result/provenance envelope and errors
  security.py     Authentication primitives, role checks, encrypted vault
  storage.py      SQLite repository, sessions, evidence, cache and audit
  connectors.py   Validated DNS/RDAP/CT/website/HIBP/OTX/URLhaus collectors
  analysis.py     CDR, geospatial and offline TShark services
  phone.py        Offline phone numbering-region estimates, no device tracking
  subdomains.py   Passive discovery, bounded DNS checks and CSV export
  reporting.py    Case snapshot and PDF/CSV writers
examples/         Configuration and explicit synthetic datasets
scripts/          Linux install/build and reproducible verification
tests/            Unit, integration, role/security and desktop checks
artifacts/        Generated synthetic QA previews and live smoke summaries
launcher.py       PyInstaller entry point
pyproject.toml    Dependencies and desktop CLI
.github/workflows/tests.yml  Linux CI (includes TShark)
```

Modules do not depend on the desktop UI. `Result` carries attribution, timestamps, status, freshness and errors. `Session` enforces service permissions. The SQLite repository opens a connection per operation with foreign keys and WAL enabled, making worker calls safe. Schema version is 1. Database I/O is contained in `storage.py` with small monitor bookkeeping in the UI; a future PostgreSQL backend requires replacing the repository/transactions and implementing migrations. PostgreSQL is not selectable in this release.

## Phases and verification

| Phase | Source delivered | Verification |
| --- | --- | --- |
| 1: foundation | App, UI, config, SQLite, local users/cases | Offscreen desktop navigation, persistence, worker GUI-thread callbacks |
| 2: OSINT | DNS, RDAP, CT, website metadata | Live DNS/RDAP/CT using example.com; deterministic validation/cache/HTTP tests |
| 3: breach/threat | HIBP catalog/exposure, OTX, URLhaus, watches/feed timer | Live public HIBP catalog; simulated authenticated HIBP and URLhaus API contracts |
| 4: offline forensics | CSV/XLSX CDR and TShark adapter | Synthetic CDR calculations/XLSX; simulated TShark process; real-TShark test when installed |
| 5: geospatial/reports | Location/tower schemas, Folium, Plotly, PDF/CSV | Synthetic import and HTML assertions; reports exported/rendered and inspected |
| 6: hardening/package | Role checks, lockout, vault, bounds, audits, PyInstaller script, Linux CI | Security/regression tests; Linux installation, actual Linux bundle and credentialed APIs still require target-system validation |

Verification in the current Windows environment: **97 tests passed, 1 skipped** (real TShark is absent). The latest audit confirmed live DNS, RDAP, public website metadata and the HIBP catalog; crt.sh returned HTTP 502. The subdomain-address follow-up independently verified live A/AAAA resolution for www.example.com; see `artifacts/subdomain-address-check.json`. See `artifacts/live-source-checks.json`, `artifacts/website-source-check.json`, and [the complete function review](FUNCTION_VERIFICATION.md). No API keys were provided, so authenticated HIBP, OTX and URLhaus were not checked against live accounts.

A synthetic 100,000-row CDR workload with 1,000 relationships completed in **1.029 seconds** on this Windows/Python 3.12 environment, with expected totals verified. This is a single workload measurement, not a Linux performance guarantee; see `artifacts/performance-checks.json` and `scripts/benchmark_cdr.py`.

```bash
.venv/bin/python -m pytest -q
.venv/bin/python scripts/verify_demo.py
# Optional Internet access; only public metadata and example.com
.venv/bin/python scripts/check_public_sources.py
```

Windows equivalents use `.\.venv\Scripts\python.exe`. Visual verification generates dashboard/CDR screenshots, a synthetic report PDF/CSV, a relationship graph and a map. It creates a temporary test database and does not populate the real user workspace. Linux CI is provided but has not been executed from this Windows workspace.

For packaging, build on Linux:

```bash
bash scripts/package-linux.sh
./dist/CyberIntelSuite/CyberIntelSuite
```

PyInstaller does not cross-compile Linux binaries from Windows. TShark is an external dependency and must remain installed on the destination machine. Re-run the test suite and smoke-test the bundle on Kali/Ubuntu before distribution. Dependency versions from this tested environment are recorded in `requirements-tested-windows.txt`; platform-independent constraints remain in `pyproject.toml`.

## Troubleshooting

- Qt cannot load `xcb`: install the Linux libraries above and run in a desktop session with a valid display. `QT_QPA_PLATFORM=offscreen` is for automated verification, not interactive use.
- Source is unavailable: inspect the displayed source error. Verify Internet/DNS access, HTTPS endpoint configuration, credentials, subscription and domain verification. TLS failures are not bypassed. Long Retry-After responses stop collection and tell you when to retry.
- PCAP analysis unavailable: check `tshark --version` and PATH. Use smaller captures for timeout/packet limits. No root privileges are required to read your own capture file.
- Import fails: match the documented column names, timestamp offsets, direction values, coordinate ranges and size limits. Convert legacy `.xls` to `.xlsx` first.
- Evidence hash mismatch: retain the stored copy and investigate its alteration; do not overwrite the original or silently re-hash it.
- Credential vault cannot unlock: verify the separate passphrase. Restore from your authorized encrypted backup if the vault is corrupted; there is no password bypass.
- Report/map/graph unavailable: select a case with saved findings, or restore a saved analysis before opening a visual. Graphs/maps open in the system browser. Offline Folium needs vendored CDN assets.
- Logs: inspect `application.log` in the selected workspace. Back up the workspace while the app is closed so the SQLite database/evidence/vault remain consistent.

## Nmap IP scans

Restart the app and open **Nmap IP scan**. Enter up to 16 individual IP addresses, confirm ownership or permission, and choose TCP ports (blank selects the top 100; custom selection allows up to 1000). IPv4 and IPv6 use separate batches. The background scan records port states, service names, products, versions, CPEs, confidence, TLS tunnel indicators, OS hints, and script output. Select a case before scanning to retain findings in the existing reports and audit trail.

Install [Nmap](https://nmap.org/download.html), ensure `nmap --version` works in your terminal, then restart the app. The Linux installer now includes Nmap; packaged builds still need it installed separately. TCP connect scanning does not require the app to run as administrator. This feature does not scan UDP or perform full OS fingerprinting.

The optional [Vulners script](https://nmap.org/nsedoc/scripts/vulners.html) sends detected service/version/CPE information to vulners.com and requires internet access. Its version-based matches are potential vulnerabilities, not confirmed exploitability. Missing versions, backported patches, provider failures, and host timeouts limit results; empty findings do not establish safety. Each host has a 120-second timeout; the complete process also has a bounded timeout. Fixed arguments are passed without a shell; arbitrary Nmap options and scripts are not accepted.

Verification here uses synthetic XML and a mocked Nmap process, including the GUI-to-case workflow. Nmap is absent on this Windows machine, so no live Nmap scan has been verified.

## Provider references

- [Qt for Python](https://doc.qt.io/qtforpython-6/gettingstarted.html)
- [RDAP bootstrap redirect service](https://about.rdap.org/)
- [HIBP API and authorization](https://haveibeenpwned.com/api/v3)
- [URLhaus query API and Auth-Key requirements](https://urlhaus-api.abuse.ch/)
- [OTX official SDK/API contract](https://github.com/AlienVault-OTX/OTX-Python-SDK)
- [TShark reference](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Certificate transparency source](https://crt.sh/)
- [Cert Spotter fallback API and rate limits](https://sslmate.com/help/reference/ct_search_api_v1)

Only public and authorized metadata/files are used. No stolen password databases, private telecom access, access-control bypass or malware-download operations are implemented.
