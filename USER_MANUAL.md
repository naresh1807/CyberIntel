# CyberIntel Suite — User Manual

For the current development release, version 0.1.0. Updated 5 October 2026.

CyberIntel is a desktop tool for public infrastructure lookups, authorized phone validation, threat enrichment, offline evidence analysis, and case reports. It opens directly without login or registration. Use a graphical desktop session on Kali.

## Contents

1. [Install, start, and update](#1-install-start-and-update)
2. [First investigation and navigation](#2-first-investigation-and-navigation)
3. [Settings and API credentials](#3-settings-and-api-credentials)
4. [Live OSINT](#4-live-osint)
5. [Subdomain discovery](#5-subdomain-discovery)
6. [Phone estimates and Twilio](#6-phone-estimates-and-twilio)
7. [Nmap IP scan](#7-nmap-ip-scan)
8. [Breach intelligence](#8-breach-intelligence)
9. [Threat intelligence](#9-threat-intelligence)
10. [Cases and evidence](#10-cases-and-evidence)
11. [CDR analysis](#11-cdr-analysis)
12. [Network forensics](#12-network-forensics)
13. [Geospatial analysis](#13-geospatial-analysis)
14. [Reports, saved findings, and status](#14-reports-saved-findings-and-status)
15. [Troubleshooting and backups](#15-troubleshooting-and-backups)

## 1. Install, start, and update

Requirements: Python 3.11 or newer, internet access for installation and online lookups, and a Linux graphical desktop. Run the app as your regular user.

First installation on Kali:

```bash
sudo apt update
sudo apt install -y git
cd ~
git clone https://github.com/naresh1807/CyberIntel.git
cd CyberIntel
bash scripts/install-linux.sh
.venv/bin/python -m cyberintel
```

The installer uses apt for desktop libraries, Nmap, and TShark, then installs Python dependencies in `.venv`. If TShark asks whether ordinary users should be allowed to capture packets, choose **No** for this tool's offline analysis workflow.

To start an existing installation:

```bash
cd ~/CyberIntel
.venv/bin/python -m cyberintel
```

To update, close the app first:

```bash
cd ~/CyberIntel
git pull --ff-only
.venv/bin/python -m pip install -e .
.venv/bin/python -m cyberintel
```

These commands assume you cloned into your home directory. Adjust `cd` if you chose another folder. If Git reports local changes or divergent history, retain those changes and resolve the conflict before updating.

Windows source installation launches with `.\.venv\Scripts\python.exe -m cyberintel`. Linux installation and packaging have not been independently verified from the development Windows machine.

## 2. First investigation and navigation

1. Open **Cases & evidence** and click **+ New case**, or use **+ New investigation** on Overview.
2. Enter a title and scope/authority notes.
3. Select the case in the **ACTIVE CASE** selector at the top.
4. Open a module from the sidebar and collect or analyze data.
5. Review the table and the detailed result below it.
6. Open **Reports & audit** to review saved findings or export a report.

Overview displays case/evidence/finding counts, activity by UTC date, and recent findings. Filters search across table columns; clear the filter if expected rows disappear. Click a column heading to sort.

Online results without an active case can be viewed and cached but are not retained as case findings. Evidence imports, offline analysis, reports, and case monitors require a case. Changing cases clears the displayed module results; saved findings remain in their original case.

Tasks run in the background. Read the message at the bottom and wait for completion before starting another task, changing cases, or closing the app.

## 3. Settings and API credentials

Open **Settings**, enter the credentials you need, and click **Save credentials**. There is no vault, unlock passphrase, login, or registration step. Click an eye icon to show or hide a field. Fields start hidden when the app opens.

| Field | Purpose |
| --- | --- |
| HIBP subscription key | Authorized email and verified-domain breach checks |
| OTX API key | AlienVault OTX indicator enrichment |
| URLhaus Auth-Key | URLhaus metadata queries and recent feed |
| Twilio Account SID | Account identifier starting with `AC` |
| Twilio API key SID | API key identifier starting with `SK` |
| Twilio API key secret | Secret belonging to that API key |

An Account SID and API key SID are different. Use an API key belonging to the intended Twilio account with the required access. Replace any secret exposed in chat, screenshots, or source code.

Saved credentials load automatically. They are stored without encryption in `api-credentials.json` in the app's data directory, with private Linux file permissions. Do not share that file or include it in uploads. To remove a saved key, clear its field and save again. Previously encrypted `vault.enc` files are preserved but are no longer read; enter those keys again in Settings.

## 4. Live OSINT

Choose an operation, enter its supported target, then click **Collect**.

| Operation | Target | Results |
| --- | --- | --- |
| DNS records | Domain, such as `example.com` | A, AAAA, MX, NS, TXT, SOA, CAA |
| RDAP registration | Domain or IP address | Public registration metadata, where supplied |
| CT / public subdomains | Domain | Certificate-observed names and bounded DNS enrichment |
| Website metadata | Domain | Page title, selected metadata, server/content-type headers |

Enter domains without `https://`, paths, or spaces. For an IP such as `103.192.199.216`, use **RDAP registration**. The DNS, CT, and website options require domain input in this release.

Website metadata requires its authorization checkbox. It makes an HTTPS request to the site's home page; it does not discover hidden pages or directories. Use **Refresh cache** when you need a new provider request rather than a recent cached response.

## 5. Subdomain discovery

1. Open **Subdomain discovery**.
2. Enter a root domain, for example `example.com`.
3. Leave **Resolve IPs (first 100)** checked to obtain IPv4/IPv6 addresses, or uncheck it for a names-only lookup.
4. Click **Find subdomains**.

The app tries crt.sh, then Cert Spotter if the first provider fails. Names appear before DNS checks finish. Wait for final completion to retain enriched results in the active case. Sources, errors, and warnings are visible in the details panel.

Results are limited to observed descendants of the domain. Wildcard patterns appear separately in details; a wildcard certificate does not identify a specific host. Provider coverage, rate limits, and the five-page fallback limit mean discovery is not exhaustive. Partial results are explicitly labeled.

| Address display | Meaning |
| --- | --- |
| IPv4/IPv6 addresses | DNS returned address records |
| No A record / No AAAA record | That address family has no record |
| Name does not exist | Resolver reported NXDOMAIN |
| DNS lookup failed | Query failed; this does not prove absence |
| Not checked | This name has not yet been checked |

Filter the table and use **Check DNS for filtered names (max 100)** to refresh addresses or check remaining names. **Export filtered CSV** exports the visible names and provenance. DNS resolution does not prove that a website is available or that you own the host.

## 6. Phone estimates and Twilio

Both features are on **Phone region estimate**.

### Offline estimate

Enter an international phone number beginning with `+`, or enter a national number and a country code such as `IN`. Click **Estimate numbering region**.

This uses offline numbering metadata for country, allocation area where available, number type, original carrier, and possible time zones. It does not identify the subscriber, reveal an address, or determine current device location. Portability and roaming can make allocation labels inaccurate.

### Twilio lookup

1. Save your Account SID, API key SID, and API key secret in **Settings**.
2. Enter your own or another authorized phone number using `+country-code` and digits only. For India, use `+91` followed by the ten-digit number, without spaces.
3. Check **I am authorized to send this phone number to Twilio for lookup**.
4. Initially leave **Include carrier/type lookup** unchecked.
5. Click **Twilio phone lookup**.
6. Review the status, table, and detailed response.

Default validation can return fields such as `valid`, formatted number, country code, and validation errors. It does not return a person's name or address. To request carrier and line type, enable **Include carrier/type lookup** and run again; charges, provider access rules, and coverage restrictions apply. Missing carrier data can include a provider error code in details.

This integration does not retrieve breach records, home addresses, or GPS coordinates. A valid number is not proof that a person owns it or that the phone is currently reachable. [Twilio lookup reference](https://www.twilio.com/docs/lookup/v2-api).

## 7. Nmap IP scan

1. Open **Nmap IP scan** and select a case if you want the result retained.
2. Enter up to 16 individual IP addresses separated by commas. Scan IPv4 and IPv6 in separate batches. Hostnames and address ranges are not accepted.
3. Leave ports blank for the top 100 TCP ports, or enter a custom selection such as `22,80,443,8000-8010`, up to 1,000 ports total.
4. Confirm ownership or permission to scan.
5. Optionally enable **Vulners lookup**.
6. Click **Scan IPs** and wait for completion.

Results include TCP port states, detected service/product/version, confidence, CPEs, TLS tunnel indicators, OS hints, and script findings. OS hints are not full OS fingerprinting. UDP scanning is not included. Host summaries and timeout information are in details.

Vulners sends detected service/version/CPE information to its external provider. Its matches are potential vulnerabilities requiring validation, not proof of exploitability. No match does not establish safety. Nmap must be installed and available on PATH; check with `nmap --version`.

## 8. Breach intelligence

Choose the operation and click **Collect**:

- **Public breach catalog:** no target or HIBP key required; lists public breach metadata.
- **Authorized email exposure:** enter an authorized email, configure an HIBP subscription key, and confirm authorization.
- **Verified domain exposure:** enter a domain verified with the provider, configure the required key/subscription, and confirm authorization.

Domain responses are reduced to breach counts; email aliases are not retained. This module does not download stolen databases or passwords.

For an active case, use **Add authorized exposure watch**, **Check watches now**, or the monitor checkbox. Monitoring runs every 15 minutes while the app is open. The first successful result establishes a baseline; later changes can produce alerts. Maximum 25 watches per case. **Remove selected watch** deletes a selected watch.

## 9. Threat intelligence

In **Threat intelligence**, select URLhaus or AlienVault OTX, enter a supported IP/domain/URL, and click **Collect**. Configure the relevant API credentials. **URLhaus recent feed** needs no target; the optional feed timer runs every 15 minutes for the active case while the app is open.

URLhaus returns allowed metadata about reported URLs. OTX reports community pulse associations. The app does not visit indicator URLs or download malware. Severity is a review signal: active URLhaus malware distribution can be high, historical association medium, and missing matches unknown. Unknown does not mean safe.

## 10. Cases and evidence

Use **Attach evidence** in **Cases & evidence**, or **Import file** on an analysis page.

1. Select a case and choose the file.
2. Enter its source and acquisition timestamp, including UTC offset.
3. Select the provenance kind: actual, inferred, or synthetic.
4. Confirm permission to possess and analyze it.
5. Wait for the file to be copied and hashed.

The app stores a managed copy and SHA-256 digest; it does not modify the original. Use **Verify hashes** or **Verify evidence hashes** to check the stored copies. If a hash differs, retain the affected file and investigate before analysis.

Synthetic practice data is supplied in `examples/synthetic_cdr.csv`, `synthetic_gps.csv`, and `synthetic_towers.csv`. Import it with source `Synthetic fixture` and kind `synthetic`.

## 11. CDR analysis

Attach a CSV or XLSX file, open **CDR analysis**, select the evidence, then click **Analyze evidence**. Required columns:

```csv
caller,callee,timestamp,duration_seconds,direction
```

Numbers use 3–20 digits with optional leading `+`. Timestamps need an offset, for example `2026-10-05T10:00:00+05:30`. Duration is a finite nonnegative number; direction is `incoming` or `outgoing` in the supplied subscriber context.

Results include call counts, total/mean duration, directional counts, hourly/daily UTC activity, and weighted caller-to-callee relationships. **Open relationship graph** opens an HTML graph in your browser. Graphs are limited to 2,000 edges.

CSV/XLSX analysis accepts up to 50 MiB and 100,000 rows. Use `.xlsx`, not legacy `.xls`; macros are rejected, and only the first worksheet is read.

## 12. Network forensics

Attach a PCAP/PCAPNG file, open **Network forensics**, select the evidence, and click **Analyze evidence**.

TShark reads the existing file offline. The module summarizes protocols, bytes, connections, and DNS queries, with review heuristics. It does not capture live traffic or decrypt it. Check installation with `tshark --version`.

Limits: 200 MiB, 500,000 packets, and a 120-second processing timeout. Split larger captures with Wireshark/editcap. Heuristics identify items for review, not confirmed attacks.

## 13. Geospatial analysis

Attach CSV/XLSX evidence, open **Geospatial**, select the appropriate mode and evidence, then click **Analyze evidence**.

GPS/location columns:

```csv
latitude,longitude,timestamp,source,record_kind
```

Tower inventory columns:

```csv
tower_id,latitude,longitude,source
```

Use valid coordinate ranges and timezone-aware timestamps for location records. Location kinds are `actual`, `inferred`, or `synthetic`; the import classification can restrict how records are labeled.

Click **Open location map** to open an HTML map in your browser. Marker colors distinguish provenance and infrastructure. Maps support up to 10,000 records. Tower coordinates identify infrastructure, not a subscriber's position. No coordinates are generated from a phone number or IP address.

OpenStreetMap tiles are optional and make external browser requests. Folium's map assets also use public CDNs, so fully disconnected maps need additional asset preparation.

## 14. Reports, saved findings, and status

Open **Reports & audit** with a case selected:

- **View selected finding:** inspect the stored result.
- **Restore selected analysis to module:** display a saved finding on its module page; this is not a fresh lookup.
- **Export case PDF / Export case CSV:** choose where to save a case report.
- **Verify audit chain:** check consistency of retained audit entries.

Reports include findings, source references, collection times, and evidence/integrity information. Graphs and maps are separate HTML outputs. Protect reports because they may contain case details or authorized personal data.

| Status | Interpretation |
| --- | --- |
| Live | Provider responded during that collection |
| Cached / fresh | Stored response within the configured freshness window |
| Cached / stale | Older stored data; check the original timestamp and error |
| Unavailable | Collection failed; not a successful empty result |
| Offline | Local analysis or offline metadata |
| Synthetic | Explicitly labeled test data |

Audit-chain checks detect inconsistencies in retained entries but are not externally anchored and do not certify immutable evidence history.

## 15. Troubleshooting and backups

| Symptom | What to check |
| --- | --- |
| Installer: No such file or directory | Run `pwd`, enter the cloned `CyberIntel` folder, and check `ls scripts/install-linux.sh`. Clone the repository if needed. |
| Installer fails during apt or pip | Read the error immediately before the stage message. Check internet access, apt configuration, available disk space, and `python3 --version`. |
| Qt/xcb or display error | Run from a graphical desktop, install the script's desktop libraries, and check `echo "$DISPLAY"`. Offscreen mode is for automated checks. |
| Subdomains empty | Clear the table filter, enter a domain without a URL/path, and read the result status/details. Refresh once; repeated requests may trigger rate limits. |
| crt.sh 502 | The provider failed; the app should try Cert Spotter. Both may be unavailable or rate limited. Update the app if fallback is missing. |
| IP rejected in Live OSINT | Choose RDAP for IP input; DNS, CT, and website metadata require a domain. |
| Twilio: no result | Save all three credentials, use digits-only `+country-code` format, check authorization, and click **Twilio phone lookup**. Inspect the displayed error/details. |
| Twilio authentication/subscription error | Verify a replacement API key/secret belongs to the intended account and has Lookup access. Do not substitute Account SID for API key SID. |
| Twilio has validation but no carrier | Enable carrier/type lookup if needed. Inspect `error_code` and coverage; the optional package may cost money. |
| Lookup feels slow | Wait for the bottom progress message. Names appear before DNS completes. Uncheck Resolve IPs for a names-only result. Network/provider delays still apply. |
| Nmap or TShark missing | Check `nmap --version` or `tshark --version`; install the tool and ensure it is on PATH. |
| Offline evidence absent from selector | Select its case, confirm the file extension is supported, and attach evidence before analysis. |
| Import rejected | Check column names, first worksheet, offsets, values, provenance, and file/row limits. |
| Evidence hash mismatch | Preserve the affected copy and investigate its alteration before continuing. |
| Report unavailable | Select a case. Restore a saved analysis before opening its graph/map. |

Default app data is stored at `~/.local/share/cyberintel`. The source checkout and data directory are separate. Updating Git does not replace your case database.

Close the app before backing up the entire data directory, including the database, evidence, credentials, and configuration. Keep backups private. A custom workspace can be opened with:

```bash
.venv/bin/python -m cyberintel --data-dir /path/to/workspace
```

For support, provide the module, operation, target type, app commit (`git log -1 --oneline`), and exact displayed error. Hide credentials and unnecessary personal information in screenshots. Logs are in `application.log` in the selected data directory; they may contain less detail than the on-screen error.

Live paid Twilio access, credentialed provider subscriptions, and actual Nmap scans have not been verified with your Kali account. Test a small authorized lookup first and assess the source and timestamp before relying on a result.
