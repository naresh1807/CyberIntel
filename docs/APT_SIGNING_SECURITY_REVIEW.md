# Production APT Signing Security Review

Review baseline: 7d650a9 plus the local changes described below. Expected public
primary fingerprint: F1C454E3BB40C77AB236828DCB222DFEAD382DFC.
Expected UID: Thatikonda Naresh Goud <nareshthatikonda143@gmail.com>; Ed25519.
No owner private key/passphrase was requested, accessed, generated or replaced.

## Gate results

PASS below means source review and executed local tests only. Actual owner-key
and GitHub execution are separately NOT TESTED; no VM lifecycle result is inferred.

| Gate | Status | Evidence/scope |
| --- | --- | --- |
| Fingerprint verification | PASS | Import is independently inspected before signing; malformed/missing/wrong/whitespace/development configurations tested, as are invalid/expired keys, UID, algorithm and capabilities. Mock production metadata only. |
| Secret handling | PASS | Secrets popped immediately from Python environment, import via stdin, import output suppressed, passphrase file0600; shell unsets secrets before verification children. Success/import/identity/signing failure checks verify no placeholder leakage. Real Environment scope NOT TESTED. |
| Temporary GPG isolation | PASS | umask077, isolated0700 GNUPGHOME outside source, agent termination, Python finally and workflow if-always cleanup; success/failure regression tests. |
| Signature generation | PASS | Explicit --local-user selection; real disposable development fixtures generate Release, InRelease and Release.gpg. Owner-key generation/signing NOT TESTED. |
| Signature verification | PASS | Both signatures checked with gpgv and an independent fingerprint pin; rejects another signer even with both public keys trusted. Real production signatures NOT TESTED. |
| APT hash verification | PASS | Signed Release SHA256/size validates Packages/Packages.gz, bounded decompression matches Packages, package hashes/control fields checked. |
| Tamper tests | PASS | Modified Packages, Packages.gz, Release, InRelease, Release.gpg, package payload, both missing signatures and a different test signer rejected. Runtime copy-based checks preserve the original. |
| Development-key isolation | PASS | Approved production pin enforced before import and in production verifier; historical development pin rejected, no fallback. |
| Workflow permissions | PASS | Default contents: read; signing inherits read only, Pages deployment alone pages/id-token write, release publication alone contents write. |
| Action pinning | PASS | All actions pinned to immutable 40-character SHAs; regression assertion. This does not certify upstream action internals. |
| Secret leakage scan | PASS | Bounded source/artifact scanner and tracked private-key-header search; no detected material. Unknown owner passphrase is not accessed or searched. |
| Full test suite | PASS | 451 passed, no failed/skipped/xfailed; 37.08s, artifacts/production-signing-review/pytest.xml. |
| APT/release regressions | PASS | Dedicated signing/APT/release group: 65 passed in2.66s; included in full suite. |
| Go worker tests | PASS | Official workflow-pinned Go1.26.8 archive downloaded into /tmp, published SHA256 verified; go test -race ./... passed for cyberrecon/dns-worker. |
| Production workflow | NOT TESTED | Protected signing dry-run implemented but not dispatched on GitHub. Environment settings/secrets/protections not independently inspected. |
| Public APT hosting | BLOCKED | No qualified HTTPS URL configured; production gate rejects missing URL with supplied public maintainer identity. |
| Kali qualification | BLOCKED | Clean disposable installed desktop environment unavailable for this review. |
| Parrot qualification | BLOCKED | Required clean installed desktop environment unavailable. |
| Upgrade | BLOCKED | Required real old-to-new installed package transaction/data preservation not executed. |
| Remove | BLOCKED | Required disposable installed-system transaction not executed. |
| Purge | BLOCKED | Required disposable installed-system transaction not executed. |
| Reinstall | BLOCKED | Required disposable installed-system transaction not executed. |
| Reboot | BLOCKED | Required clean supported-system reboot persistence not executed. |
| Overall | BLOCKED | Production release NOT APPROVED. |

## Changes and manual next action

Changed .github/workflows/release-apt.yml, scripts/sign_cyberrecon_release.py,
added scripts/test_cyberrecon_apt_tampering.py, extended tests/test_apt_repository.py
and tests/test_production_signing.py, and updated the three APT/readiness documents
plus this review. Existing architecture and production qualification checks remain.

Owner configuration: GitHub Settings → Environments → cyberrecon-production.
Add the public variable APT_SIGNING_FINGERPRINT with the fingerprint above and
CYBERRECON_MAINTAINER with the public UID above. Enter APT_SIGNING_PRIVATE_KEY
and APT_SIGNING_PASSPHRASE privately as Environment secrets, remove any
repository-level signing duplicates, require reviewers/prevent self/bypass approval
where available, restrict deployment to main, review workflows accessing this
Environment and protect release-code changes. Configure/protect github-pages
separately; leave candidate workflows without production secrets. Workflow code
cannot prove Environment-vs-repository secret origin; owner settings review is required.

Exact next action: review/merge these changes, then dispatch release-apt.yml on main
with signing_dry_run=true, publish=false and refresh_only=false. Approve the
protected jobs and review public artifacts, cleanup and signature/tamper results.
Do not select publish until real HTTPS hosting, immutable exact-commit Kali/Parrot
lifecycle evidence and every release gate are complete. Only then configure
APT_PUBLIC_URL, RELEASE_QUALIFIED_COMMIT and approved RELEASE_QUALIFICATION_JSON
and separately approve publication. Never enter private material in chat/source/issues.
