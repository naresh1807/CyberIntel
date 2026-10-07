# CyberRecon v0.2.0 production release readiness

Signing setup baseline: `fddfafc`. APT phase baseline: `c1cdeb4`. Previous final-gate baseline: `c1fafb8`. This phase includes uncommitted signing setup
changes and does not qualify an immutable production commit. Runtime and Go
protocol: **0.2.0**. Candidate Debian package: **cyberrecon 0.2.0-5**.
Compatibility Python distribution/desktop: **cyberintel-suite / CyberIntel 0.1.0**,
retained intentionally. Primary command/module: cyberrecon / python -m cyberrecon.
No debian/ tree exists; scripts/build-cyberrecon-deb.py generates Debian metadata.

## Release blocker matrix

| Gate | Status | Evidence |
| --- | --- | --- |
| Full test suite | PASS | .venv/bin/python -m pytest -q --junitxml artifacts/production-signing-setup/pytest.xml: 437 passed, 0 failed, 0 skipped, 0 xfailed (37.56 seconds); prior APT baseline 421 passed. |
| Kali desktop | BLOCKED | Live Kali 2026.3 source GUI passed as UID1000 on XFCE/X11 Qt xcb; installed clean desktop VM is unavailable. No qemu-system-x86_64/virsh/VBoxManage or /dev/kvm; sudo -n true requires a password. Evidence: artifacts/final-production-gate/desktop/desktop.json. |
| Parrot desktop | BLOCKED | No suitable Parrot Security amd64 desktop VM/environment available. Historical core-image package tests do not satisfy this gate. |
| Fresh install | BLOCKED | No disposable desktop VM with package-management privilege. Production host is not modified or rebooted. Staged archive extraction is not an installed package transaction/menu test. |
| Upgrade | BLOCKED | No disposable desktop VM with package-management privilege. Production host is not modified or rebooted. Staged archive extraction is not an installed package transaction/menu test. |
| Reboot persistence | BLOCKED | No disposable desktop VM with package-management privilege. Production host is not modified or rebooted. Staged archive extraction is not an installed package transaction/menu test. |
| Remove | BLOCKED | No disposable desktop VM with package-management privilege. Production host is not modified or rebooted. Staged archive extraction is not an installed package transaction/menu test. |
| Purge | BLOCKED | No disposable desktop VM with package-management privilege. Production host is not modified or rebooted. Staged archive extraction is not an installed package transaction/menu test. |
| Reinstall | BLOCKED | No disposable desktop VM with package-management privilege. Production host is not modified or rebooted. Staged archive extraction is not an installed package transaction/menu test. |
| GUI launcher | BLOCKED | No disposable desktop VM with package-management privilege. Production host is not modified or rebooted. Staged archive extraction is not an installed package transaction/menu test. |
| Non-root CLI | PASS | .venv/bin/cyberrecon --version (0.2.0), --help and --doctor executed as UID1000; source CLI only. Installed non-root CLI remains part of VM gates. |
| Scope enforcement | PASS | Full suite covers include/exclude, wildcard/apex, IPv4/IPv6 CIDR, private IP authorization, DNS exclusions and scope-before-transport. |
| APT repository | BLOCKED | Production HTTPS repository and default-APT public installation unavailable. Development repository signatures/checksums are historical local evidence only. |
| Repository signing | BLOCKED | Owner supplied expected production fingerprint F1C454E3BB40C77AB236828DCB222DFEAD382DFC. Actual imported production key, protected secrets and signing are NOT TESTED. No private key generated/committed for production. |
| License | PASS | LICENSE is MIT; pyproject SPDX expression, Debian copyright, README and GUI About agree; compatibility distribution remains0.1.0 by design. |
| Maintainer metadata | BLOCKED | RELEASE BLOCKER: Maintainer identity required before production publication. Owner now supplied Thatikonda Naresh Goud <nareshthatikonda143@gmail.com>; Environment application/verification pending. |
| Release workflow | NOT TESTED | Workflow YAML/action pins inspected and local release gates tested. GitHub workflow execution/protected-environment configuration not verified; production v0.2.0 tag is not created. |

## Supported policy and measured environment

Primary OS targets: Kali Linux and Parrot Security, initially amd64 only. No
blanket rolling-release or Security-desktop certification is claimed. Current
execution: Kali 2026.3, kernel7.1.5+kali-amd64, Python3.14.7, UID1000, XFCE/X11,
DISPLAY=:0.0, Qt xcb. Minimum Python3.12; recommended distro Python3.13/3.14.
Current full suite ran on3.14.7; historical Parrot core subset ran on3.13.5.
Python3.12 remains a declared CI target, NOT TESTED locally. Below3.12 is
unsupported; future Python/OS versions require qualification. Do not replace
system Python. Source Python3.14 constraints are not a universal Debian lock.

The live source GUI passed rendering/icon/tab navigation, scope error handling,
1000-row cap/filtering, cancellation, report/graph generation and close/reopen
persistence with1100 synthetic assets. Latest synchronous refresh:1.03seconds.
Settings, Dashboard and Doctor are text/JSON panels; sidebar is NOT IMPLEMENTED.
Installed menu/browser report handoff and reboot are NOT TESTED. A benign Qt
accessibility warning appeared; no unhandled traceback was reported by the GUI
verifier. Window-only screenshots and JSON are under artifacts/final-production-gate/desktop.

## Security and preservation evidence

Scope, TLS, redirects, request/response bounds, parameter-value redaction,
subprocess bounds, workspace/database permissions and provider/API-key protection
passed existing regressions. Neither optional provider integration nor broad
external recon coverage is certified. No third-party active target was scanned.
Package staging tests are independent of actual APT install/upgrade/remove/purge.
The disposable lifecycle harness now scans its owned TLS target using the old
installed package before upgrading, hashes logical database state and every
JSON/CSV/HTML/PDF/graph report, and compares these after upgrade/remove/purge/
reinstall. Mutation-detection regression passes; the real revised harness remains
NOT TESTED because a privileged disposable OS is unavailable. It refuses changes
on unmarked hosts. No current system package installation/removal was attempted.

MIT is preserved. The owner has now supplied the public production identity and
fingerprint. Hosting and installed Environment secrets/protections remain unverified. No fake name/email, private production
key or public hosting endpoint was created. [Signing/rotation/recovery](APT_REPOSITORY.md)
and [compatibility migration](COMPATIBILITY_MIGRATION.md) remain documented.

## Workflow and reproducibility

Production publication is manual, main-only and protected by environment review;
Actions are pinned, credentials are not persisted and job permissions are scoped.
The gate now requires a reviewed report with APPROVED, matching commit/version,
a clean source tree and PASS/evidence for every mandatory gate, in addition to
identity, HTTPS URL and qualified SHA. Checked-in evidence is NOT APPROVED.
RELEASE_QUALIFICATION_JSON is supplied after committing/testing through protected
production environment variables; this avoids embedding a commit's own hash in
that commit. An attestation is not automatic VM proof. Configure required reviewers
and inspect evidence before enabling publication. Workflow execution remains
NOT TESTED. Only after all gates pass does publication create tag **v0.2.0**.

Build manifests record source commit/dirty state, UTC build date, SOURCE_DATE_EPOCH,
Python/OS/architecture, installed build dependency versions, Debian dependency
metadata and artifact SHA256. SHA256SUMS covers the manifest and artifacts.
Fresh checkout reproducibility is preferred; a local working-tree candidate is
not the final immutable release. See the [exact build/VM commands](RELEASE_CHECKLIST.md).
Prior development-signing and dependency-audit results are in the historical
[preparation evidence](release-evidence/production-readiness.json); they cannot
be silently promoted into current production PASS. Final phase artifact/checksum
results are recorded in release-evidence/final-production-build.json.

## Exact remaining actions

1. Commit/review this candidate, then qualify that immutable commit on disposable
Kali and Parrot Security amd64 desktop VMs with default APT behavior, normal-user
CLI/Doctor/GUI/menu, old→new data/report preservation, reboot, remove, purge and
reinstall. Preserve OS/session, package hashes and logs. Do not reboot this host.
2. Configure the owner-supplied public maintainer name/email, provision HTTPS APT hosting and an
operator-managed signing key through protected secrets; independently distribute
its public fingerprint and execute the trust/rotation/recovery checks.
3. Run the candidate GitHub workflow, review every mandatory gate and exact-commit
artifact, populate protected qualification evidence, then approve production
publication. No tag or public release is authorized by incomplete evidence.


## APT distribution phase

Production repository remains BLOCKED: public HTTPS hosting is not configured.
Production signing remains BLOCKED: production key has not been provisioned.
Clean Kali and Parrot installation through public APT: NOT TESTED.
Existing tooling is reused by .github/workflows/release-apt.yml, with signed
metadata verification and protected manual publication. Local Debian APT tests
verify development signatures/candidate indexes and reject unsigned metadata;
they do not install the package or certify production HTTPS.
See [APT release report](APT_RELEASE_REPORT.md).


## Production signing setup (owner identity supplied)

IMPLEMENTED: imported-key fingerprint/UID/Ed25519/validity/capability checks,
normalized fingerprints, umask077, temporary secret handling, if-always cleanup
and explicit production environments. APT_SIGNING_FINGERPRINT is public
configuration; APT_SIGNING_PRIVATE_KEY and APT_SIGNING_PASSPHRASE are secrets
the owner must add manually under cyberrecon-production.
Expected pin: F1C454E3BB40C77AB236828DCB222DFEAD382DFC.
Actual real-key signing, Environment settings/protections and secret availability:
NOT TESTED. Hosting and clean supported-system lifecycle remain BLOCKED.
No production key was generated, replaced, exported or committed by this agent.
See the exact owner setup in [APT operations](APT_REPOSITORY.md).

CYBERRECON v0.2.0 PRODUCTION RELEASE DECISION

**NOT APPROVED**
