# Production release readiness

This phase prepares a candidate; it does not certify a public production release.
Baseline: a1736341030de9f23b0ebcb913f40efafb2d59ee. Evidence was executed on
Kali 2026.3, Python 3.14.7, as UID 1000. No system packages were installed,
no host reboot was attempted, and no release was published.

## Verified identity and policy

CyberRecon and the Go protocol remain 0.2.0. The candidate Debian package is
`cyberrecon 0.2.0-5` (all without the worker, amd64 with the built worker).
The Python distribution remains `cyberintel-suite 0.1.0`; the independent legacy
CyberIntel desktop remains 0.1.0. Entry points are `cyberrecon.cli:main` and
`cyberintel.app:main`. Primary module: `python -m cyberrecon`.
MIT was selected with the user's authorization. LICENSE, SPDX metadata, package
copyright, GUI About and Debian metadata agree. Public maintainer name/email:
**MAINTAINER IDENTITY REQUIRED**. No personal identity or hosting URL was invented.

Minimum Python: 3.12. Recommended: the supported distribution's Python 3.13 or
3.14. Current full suite: 3.14.7; prior distribution qualification also exercised
Parrot's 3.13.5 subset. Python 3.12 is declared and covered by the existing CI
matrix but was NOT TESTED locally in this phase. Below 3.12 is unsupported;
future versions and operating-system releases require qualification. Kali 2026.3
is the measured desktop; Parrot 7.1 has historical isolated package evidence,
not current desktop certification. No blanket support for every rolling release.

Dependencies are verified from pyproject, Debian metadata and Doctor rather
than documentation alone. The source lock contains 47 measured Python 3.14
packages; it is not a universal Debian or Python 3.12/3.13 lock. Doctor reports
required Python minimums and optional tool requirements/actions. Nmap is
recommended for port scans. External tools/providers remain capability-dependent.

## Executed results and limits

| Gate | Result | Evidence/limit |
| --- | --- | --- |
| Initial full suite | PASS | 391 passed |
| Final candidate suite | PASS | 404 passed; 34.94 seconds |
| New production tests | PASS | Archive paths, secrets, package modes, identity, state/report preservation, Doctor; 13 new tests; 18 targeted tests including existing release checks |
| Go race tests/build | PASS | Existing DNS worker; static amd64 worker built |
| Python wheel/sdist | PASS | Isolated release-tool environment, pinned backend |
| Dependency re-audit | PASS | 47 packages, no known vulnerabilities; tool/feed scope only |
| Actual Kali desktop, source GUI | PASS | UID 1000, XFCE/X11, Qt xcb, screenshots and desktop.json |
| GUI cancellation/error/table/export/reopen | PASS | Owned loopback job, 1100 synthetic assets, 1000-row cap |
| TLS local target and real Nmap | PASS | Complete; 4 HTTP, 1 port, 2 APIs, 1 JavaScript record |
| Debian staging and launcher | PASS | all/amd64 staging, ownership/modes/license/icon checks |
| Development APT signatures | PASS | Both InRelease and detached Release.gpg checked with gpgv |
| Clean Kali desktop VM | BLOCKED | No VM hypervisor or /dev/kvm available; live source GUI is not a clean installed VM |
| Parrot desktop VM | BLOCKED | No Parrot desktop VM available |
| Actual 4 → 5 APT/dpkg upgrade | NOT TESTED | Staged overlay preserves state/reports; not a real package transaction |
| Actual revision-5 remove/purge | NOT TESTED | Staged removal check only; previous phase's 3 → 4 lifecycle is historical |
| Reboot persistence/application menu | NOT TESTED | Do not reboot or alter the user's production desktop |
| Public HTTPS APT/default install | BLOCKED | Hosting URL unavailable; no default distribution repository inclusion |
| Production signing/workflow execution | BLOCKED | Operator identity, key, secrets and protected environments unavailable |

Current navigation is tabs, not a sidebar. Dashboard, settings and Doctor use
text/JSON panels; rich graph/report pages are not implemented. Graph/report files
were generated, but external browser and installed menu handoff were NOT TESTED.
Large-table refresh measured 0.698 seconds and is synchronous; do not claim a
freeze-free interface. Source close/reopen persisted state; reboot did not run.
Credential providers, broad external targets and every third-party tool are not
certified by the owned local scan. Supply-chain checks are bounded heuristics,
not a complete security audit. The feed initially returned duplicate records for
one pip advisory; virtual-environment pip was upgraded from 26.1.2 to 26.2 and
re-audited successfully. System Python/pip were not changed.

Evidence paths (ignored build artifacts): `artifacts/production-release/`,
`artifacts/desktop-production-final/desktop.json`, dashboard.png/assets.png,
`dist/production-preparation/`. Historical evidence remains in
[RELEASE_QUALIFICATION.md](RELEASE_QUALIFICATION.md).

## Release decision

Candidate only: Debian revision 0.2.0-5. Do not tag it production until the exact
commit passes the [release checklist](RELEASE_CHECKLIST.md). Recommended next
application version is 0.2.1 after those gates, with an intentional coordinated
version change; this packaging phase does not arbitrarily bump runtime versions.
CyberIntel removal is not authorized; see [migration plan](COMPATIBILITY_MIGRATION.md).
