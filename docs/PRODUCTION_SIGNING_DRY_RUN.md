# CyberRecon Production APT Signing Dry Run — verified result

Updated 2026-10-08 (America/New_York). The original non-execution record below
is preserved as historical evidence and has been superseded by the successful run.

Run: [37639197830](https://github.com/naresh1807/CyberIntel/actions/runs/37639197830).
Actual commit: 1eb2eb937a743cc66f1c4e71ed6c34f5fdeeccb8.
Public GitHub REST job/step metadata independently verified:

- prepare = PASS
- sign = PASS (production import/fingerprint checks, both signature/hash checks
  and tamper checks execute in the successful signing step)
- temporary signing material cleanup = PASS (successful cleanup step)
- Pages artifact upload = SKIPPED
- deploy = SKIPPED
- publish = SKIPPED

Production pin accepted: F1C454E3BB40C77AB236828DCB222DFEAD382DFC.
The run successfully used the protected signing path. Public APT/Pages and a
GitHub Release were not published by this run. No secret value is recorded.
The signed-release artifact exists (ID11528757198); independent download/access
and raw-log leakage audit in this session are NOT EXECUTED: artifact HTTP401,
logs HTTP403. Job success is not an independent artifact inspection.
Evidence: [public run metadata](release-evidence/final-readiness-signing-run.json).

The Node24 action migration in the current local working tree postdates this
successful run. Its GitHub execution is NOT EXECUTED; a new protected nonpublishing
dry-run is required after committing/reviewing the action changes. Clean desktop
installation/lifecycle qualification remains required before production approval.

## Historical report from before the owner's successful run

# CyberRecon Production APT Signing Dry Run

Check date: 2026-10-07 (America/New_York).
Workflow: .github/workflows/release-apt.yml / CyberRecon protected APT release.
Run ID: none — NOT EXECUTED.
Commit SHA: 74556fe085cf94266514bd9ef32a0ac992b6b02f.

GitHub's public REST API confirmed main at this SHA, workflow ID377329498 active,
and zero APT workflow runs at inspection. This session has no GitHub CLI or
GH_TOKEN/GITHUB_TOKEN authentication or connected GitHub execution capability.
No workflow dispatch, Pages deployment or Release creation was attempted.
No owner production private key or passphrase was accessed/requested.

## Actual remote results

| Gate | Status |
| --- | --- |
| GitHub Environment | NOT EXECUTED |
| Production fingerprint / imported key | NOT EXECUTED |
| GPG key import / fingerprint verification | NOT EXECUTED |
| APT Release signing | NOT EXECUTED |
| InRelease verification | NOT EXECUTED |
| Release.gpg verification | NOT EXECUTED |
| Packages/Packages.gz hash verification | NOT EXECUTED |
| Package SHA256 verification | NOT EXECUTED |
| Remote tamper detection | NOT EXECUTED |
| Remote logs/artifacts secret leakage audit | NOT EXECUTED |
| Temporary GPG cleanup on runner | NOT EXECUTED |
| Actual runner APT security checks | NOT EXECUTED |
| Public publication | DISABLED — must remain disabled |
| Overall real GitHub dry-run | NOT EXECUTED |

Local tests and source assertions are recorded separately below. They do not prove
any remote or owner-key result above. Production release remains NOT APPROVED.

## Exact owner action

1. Open Settings → Environments → cyberrecon-production. Configure required
reviewers, deployment to main and release-code protections. Review/remove any
repository-level duplicate signing secrets. Set public variables:
   - APT_SIGNING_FINGERPRINT: F1C454E3BB40C77AB236828DCB222DFEAD382DFC
   - CYBERRECON_MAINTAINER: Thatikonda Naresh Goud <nareshthatikonda143@gmail.com>
2. Enter APT_SIGNING_PRIVATE_KEY and APT_SIGNING_PASSPHRASE privately as
Environment secrets in GitHub Settings only. Never send either through chat,
source files, command arguments, issue text or uploaded diagnostic files.
3. Open Actions → CyberRecon protected APT release → Run workflow → Branch main.
Leave publish unchecked (false), check signing_dry_run (true), leave refresh_only
unchecked (false). Click Run workflow and approve the protected prepare/sign jobs.
4. Record the run URL/ID and actual head SHA. Confirm deploy and publish are skipped,
and no upload-pages-artifact step executes. Review sign validation, integrity/tamper
checks and the always-run cleanup. Download only the public signed-release artifact
for cryptographic verification and credential scanning; never export runner secrets.
5. Independently verify the supplied public primary fingerprint, then use:

```bash
python3 scripts/verify_cyberrecon_apt.py <SIGNED_RELEASE_DIRECTORY>/apt --keyring <SIGNED_RELEASE_DIRECTORY>/apt/cyberrecon-archive-keyring.gpg --fingerprint F1C454E3BB40C77AB236828DCB222DFEAD382DFC --production
python3 scripts/test_cyberrecon_apt_tampering.py <SIGNED_RELEASE_DIRECTORY>/apt --keyring <SIGNED_RELEASE_DIRECTORY>/apt/cyberrecon-archive-keyring.gpg --fingerprint F1C454E3BB40C77AB236828DCB222DFEAD382DFC --production
python3 scripts/check_release_security.py --artifacts <SIGNED_RELEASE_DIRECTORY>
```

Inspect logs/artifacts privately for accidental secret material before recording
PASS. GitHub masking alone is not proof of absence. Report only statuses and safe
run links; never paste secret contents if a leak is suspected.

The current worker-enabled workflow intentionally builds/signs
cyberrecon_0.2.0-5_amd64.deb, not the all-architecture filename in the request.
The verifier checks that actual Debian architecture/control metadata agrees with
Packages and its SHA256. Existing local fixtures cover all packages indexed for
amd64; the requested all package is not claimed as a remote generated artifact.

## Remaining qualification

After a genuinely successful signing dry-run, qualify actual HTTPS-hosted
production-signature APT behavior and clean Kali/Parrot desktop installation,
non-root CLI/GUI, old-to-new data preservation, reboot, remove, purge and reinstall.
Only reviewed exact-commit evidence with every mandatory gate PASS can authorize
publication. Do not dispatch publish=true on the basis of local tests or this report.

## Executed local checks

- Full suite: PASS — 451 passed, 0 failed/skipped/xfailed in63.55s;
  .venv/bin/python -m pytest -q --junitxml artifacts/github-signing-dry-run/pytest.xml.
- Dedicated APT/release group: PASS — 65 passed in3.61s (test_production_signing,
  test_apt_repository, test_production_release, test_cyberrecon_release).
- Go worker: PASS — go test ./... using checksum-verified official Go1.26.8
  downloaded into /tmp; cyberrecon/dns-worker passed in0.002s.
- Bounded source/local artifact credential scan: PASS — 153 source files and
  29 existing local artifact files; no real GitHub run logs/artifacts available.
- git diff --check: PASS. Only this report was added in this task.

These are local results, not the requested real GitHub dry-run results.
