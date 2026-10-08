# Parrot lifecycle qualification investigation

Date: 2026-10-08. Starting commit: 931565e38d07af6b272abc5829dcef87a1eb52ad.
No production publication or signing changes.

## Remote evidence

Local checkout was clean and remote main matched the starting commit. No workflow
run on 931565e was available. GitHub authentication was unavailable, so dispatch
was NOT EXECUTED. The last inspected distribution run was
[37746000518](https://github.com/naresh1807/CyberIntel/actions/runs/37746000518)
on cc76719: Kali source tests failed and Parrot package lifecycle qualification
failed. Access to the actual Parrot job logs returned HTTP 403. Its precise remote
traceback remains unverified; do not claim the following local findings are an
independently verified account of that job's traceback.

## Reproduced qualification harness regressions

The current fixture invoked the previous 0.2.0-4 package's scanner with keywords
that historical API does not support. The exact historical source from a173634
raised `TypeError: scan() got an unexpected keyword argument 'nmap_unprivileged'`.
This was also reproduced against the real installed historical Parrot package.
The fixture now uses the old API without those keywords and sets
`NMAP_UNPRIVILEGED=1` only in the fixture process, removing any conflicting
`NMAP_PRIVILEGED` setting. Nmap documents this as the equivalent of
[`--unprivileged`](https://nmap.org/book/man-misc-options.html). The historical
adapter still uses TCP-connect scanning and the owned loopback target. Current
packages retain their explicit unprivileged option and diagnostic callback.

Separately, a successful real TLS/Nmap scan reproduced `JSONDecodeError: Extra
data: line 2 column 1` when its diagnostic JSON and final result were combined.
Diagnostics now use stderr. The lifecycle runner parses stdout separately while
preserving both streams in its evidence log. Nonzero exits and timeouts still
fail. No lifecycle, package, scope, TLS, OPEN-port or data-preservation assertion
was removed or relaxed. Production application/package code is unchanged.

## Actual local package transactions

Used the pinned Parrot core filesystem (7ac3f98c...), Python 3.13, official signed
APT repositories, and real dpkg/APT commands under disposable user namespaces.
The final run used the qualifier's default options. Initial reproduction setup
omitted cryptography and the startup verifier; those setup errors were corrected
with the workflow's existing prerequisites, without repository/workflow changes.

All 29 recorded checks passed in the final run, including install of 0.2.0-4,
upgrade to 0.2.0-5, CLI version/help/Doctor, package ownership/permissions,
offscreen GUI startup, actual installed-package TLS/Nmap scans before and after
upgrade, dpkg audit, remove, reinstall before purge, purge, fresh reinstall, and
final remove/purge. Logical database and JSON/CSV/HTML/PDF/graph report hashes
were preserved through upgrade/removal/purge/reinstallation; new workspace
permissions and post-reinstall retained user data were asserted. The package
transactions were not simulated or substituted with extraction.

Evidence: `artifacts/lifecycle-json-fix/parrot-evidence/qualification.json` and
its individual apt/dpkg/scan logs, plus `parrot-final-lifecycle.log` and
`parrot-api-before-after.log` in the same artifact parent directory.

Tested package hashes:

- 0.2.0-4: 0b7242533de362e130fc5be935d940d9841d988ab1f621f60703f8c9c077dfd5
- 0.2.0-5: 379b6773ef328f2f48da2f5119fd5f1d037aa4dc597c134e3d59542f7aa40f6c

Full native Python suite: 460 passed. Three new output-contract/API regressions
included. Go race tests passed. Workflow content, image digests and action pins
were unchanged; workflow shell validation passed. Credential/path/permission
scan checked 162 source files and one actual Debian artifact successfully. These
bounded checks are not a production signing or complete vulnerability audit.

## Mandatory remaining gates

This filesystem shares the host kernel and network, with a single UID mapping.
It is neither GitHub's exact container runtime nor a desktop VM. Local normal-user
source CLI checks passed as UID 1000; normal-user installed Parrot ownership and
permissions have not been qualified in this mapping. Offscreen GUI startup does
not prove desktop menu launch. No real reboot was performed. Signed production
package/repository verification was NOT EXECUTED.

A new exact-commit GitHub run must prove the Kali Nmap capability fix and complete
both distribution jobs. A real disposable Parrot Security amd64 desktop VM must
add normal-user installed CLI/GUI/menu checks and reboot persistence; Kali needs
the equivalent desktop/reboot evidence. Full production readiness remains pending
those gates and production signing verification. No green remote result, release,
Pages deployment, APT publication or production package is claimed.
