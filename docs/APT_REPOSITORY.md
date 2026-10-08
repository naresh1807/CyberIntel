# APT repository and signing operations

**Production status: BLOCKED.** No public HTTPS URL is available. The maintainer has supplied the
production identity below; GitHub Environment configuration remains manual. `sudo apt install cyberrecon` from the default Kali/Parrot repositories
is not supported today. GitHub Pages is a prepared hosting option, not a live
repository. Only local development signing has been executed.
**PUBLIC APT HOSTING REQUIRED. PRODUCTION SIGNING SECRETS MUST BE CONFIGURED BY THE OWNER.**

## Layout and trust

The builder creates `pool/main/c/cyberrecon/*.deb`,
`dists/stable/main/binary-amd64/Packages` and reproducible Packages.gz,
`dists/stable/Release`, `InRelease`, `Release.gpg`, and a public
`cyberrecon-archive-keyring.gpg`. Release includes SHA256 index hashes and a
seven-day Valid-Until. Package indexes carry the package hashes. amd64 is the
only advertised architecture, including all packages; arm64 is rejected until
qualified. Expiring metadata must be refreshed and re-signed before expiry.
Never disable APT authentication or freshness checking to conceal failure.

Development keys are disposable, one-day keys, labeled DEVELOPMENT ONLY and
removed after signing. They cannot serve as production upgrade trust anchors.
Production operators must maintain an offline primary key, encrypted backups and
revocation certificate, and a dedicated passphrase-protected signing subkey with
an expiry/renewal policy. Publish the full fingerprint through an independently
trusted channel before users install the public key.

## Protected workflow

`.github/workflows/release-apt.yml` is manual, main-only, and defaults to
preparation without publication. Actions use immutable commit pins; permissions
are scoped to jobs. Configure required reviewers and prevent bypass for the
`cyberrecon-production` environment and restrict deployment to main. Configure
GitHub Pages to deploy through Actions and protect `github-pages` as well.
These environment protections must be set by a repository administrator; YAML
alone cannot create them. This follows GitHub's
[secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use).

Repository variables: CYBERRECON_MAINTAINER (`Name <email>`), APT_PUBLIC_URL
(actual HTTPS repository base), RELEASE_QUALIFIED_COMMIT (exact tested commit).
Protected production-environment variable RELEASE_QUALIFICATION_JSON contains
the reviewed evidence report for that commit (schema shown in
release-evidence/final-production-gate.json). Every mandatory gate must be PASS
with evidence, decision APPROVED, source_tree_dirty false and matching version/SHA.
The checked-in report is NOT APPROVED; it cannot unlock publication. Set the
reviewed report after committing/testing the candidate so no commit must embed
its own hash. This is a human-reviewed attestation, not automatic proof of a VM.
The preparation job also requires the protected production environment when
publish=true; candidate preparation uses cyberrecon-candidate.
Environment variable: APT_SIGNING_FINGERPRINT (full 40/64 hexadecimal fingerprint).
Protected environment secrets: APT_SIGNING_PRIVATE_KEY (armored signing key
export) and APT_SIGNING_PASSPHRASE. Never paste secrets into source, commands,
logs, release artifacts or documentation. The helper imports through stdin into
0700 temporary GNUPGHOME outside the repository; passphrase file is 0600 and
removed, along with key material, after signing. No production key is supplied.

Preparation runs Python/Go tests, local TLS/Nmap verification, dependency audit,
archive checks, builds, staging verification and SHA256 manifests. Publication
requires identity, HTTPS URL and qualified SHA, then protected approval, signing,
Pages deployment, remote HTTPS signature/content verification and a GitHub release
with notes and artifacts under tag `v0.2.0`. Workflow execution is NOT TESTED in this phase.
Do not create the production tag while any gate is blocked.
Checksums detect transfer errors; signed metadata plus independent fingerprint
verification establishes repository trust. Candidate checksums are not signatures.

## Operator commands after all gates pass

Use a clean checkout of the exact VM-qualified commit. Do not run publication
until real values and protected environments exist.

```bash
gh workflow run release-apt.yml --ref main -f publish=false
# Review the prepared artifacts and run both desktop VM checklists.
# Set RELEASE_QUALIFIED_COMMIT to that exact main commit, then:
gh workflow run release-apt.yml --ref main -f publish=true
```

For local development only:

```bash
python3 scripts/build-cyberrecon-apt.py dist/candidate/cyberrecon_0.2.0-5_amd64.deb --output dist/apt-development --development-key
gpgv --keyring "$PWD/dist/apt-development/cyberrecon-archive-keyring.gpg" dist/apt-development/dists/stable/InRelease
gpgv --keyring "$PWD/dist/apt-development/cyberrecon-archive-keyring.gpg" dist/apt-development/dists/stable/Release.gpg dist/apt-development/dists/stable/Release
```

## User setup once a repository actually exists

The following is a template, NOT a working published URL. Set APT_BASE to the
actual operator-announced HTTPS base. Download the key, check its full fingerprint
against the trusted announcement, then install it. Never use apt-key/trusted=yes.

```bash
APT_BASE='https://<official-host>/apt'
EXPECTED_PRIMARY_FINGERPRINT='<INDEPENDENTLY_VERIFIED_PRIMARY_FINGERPRINT>'
(
  set -eu
  [[ "$APT_BASE" == https://* && "$APT_BASE" != *'<'* ]] || { echo 'Set the actual official HTTPS base'; exit 1; }
  [[ "$EXPECTED_PRIMARY_FINGERPRINT" =~ ^([A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$ ]] || { echo 'Set the independently verified fingerprint'; exit 1; }
  apt_setup_tmp=$(mktemp -d)
  trap 'rm -rf -- "$apt_setup_tmp"' EXIT
  mkdir -m 0700 "$apt_setup_tmp/gnupg"
  curl --fail --proto '=https' --tlsv1.2 "$APT_BASE/cyberrecon-archive-keyring.gpg" -o "$apt_setup_tmp/cyberrecon.gpg"
  apt_key_details=$(gpg --batch --no-options --homedir "$apt_setup_tmp/gnupg" --show-keys --with-colons "$apt_setup_tmp/cyberrecon.gpg")
  [[ $(printf '%s\n' "$apt_key_details" | awk -F: '$1=="pub" {n++} END {print n+0}') == 1 ]] || { echo 'Expected exactly one primary public key'; exit 1; }
  apt_key_fingerprint=$(printf '%s\n' "$apt_key_details" | awk -F: '$1=="fpr" {print $10; exit}')
  [[ "$apt_key_fingerprint" == "${EXPECTED_PRIMARY_FINGERPRINT^^}" ]] || { echo 'Fingerprint mismatch'; exit 1; }
  sudo install -d -m 0755 /etc/apt/keyrings
  sudo install -m 0644 "$apt_setup_tmp/cyberrecon.gpg" /etc/apt/keyrings/cyberrecon.gpg
  printf 'deb [arch=amd64 signed-by=/etc/apt/keyrings/cyberrecon.gpg] %s stable main\n' "$APT_BASE" | sudo tee /etc/apt/sources.list.d/cyberrecon.list
  sudo apt update
  apt-cache policy cyberrecon
  sudo apt install cyberrecon
  cyberrecon --version
  cyberrecon --doctor
  cyberrecon --help
)
```

Validate this sequence on both clean VMs with normal APT defaults before claiming
public installation works. For rotation, distribute the new public key using the
old trusted channel/key, allow overlap, announce both fingerprints and expiry,
then retire the old subkey. On compromise stop signing/publication, revoke the
affected key, announce the incident independently and require a verified new
trust anchor; signing a replacement with a compromised key is insufficient.
Keep package files immutable; publish new versions for changes. Archive previous
signed metadata/artifacts and evidence for rollback, without retaining private
keys in repository backups or upload paths.


## Verification, hosting and maintenance

The existing builder still uses apt-ftparchive. Release SHA256 authenticates
Packages/Packages.gz; those indexes authenticate package bytes through SHA256.
The new verifier also checks both GPG signatures against an independently pinned
fingerprint, identical Release/InRelease payloads, validity dates, bounded gzip,
architecture/version/control fields, paths and private-key leakage. It rejects
development labels with --production. A local verifier PASS is not proof of a
hosted repository or clean distribution install.

```bash
python3 scripts/verify_cyberrecon_apt.py <LOCAL_APT_DIRECTORY> --keyring <TRUSTED_PUBLIC_KEYRING> --fingerprint <TRUSTED_SIGNER_OR_PRIMARY_FINGERPRINT> --production
```

GitHub Pages deployment uses the conventional repository root, so APT_PUBLIC_URL
must point to that deployed root, not an invented /apt directory. Obtain the
actual Pages URL from repository Settings/Pages or deployment output. Configure
HTTPS, protected production/Pages environments and independent key distribution
before publishing. The owner supplied the expected public production fingerprint;
the actual HTTPS URL and independently distributed public key remain unverified.

Release metadata expires after seven days. Before expiry, re-run the manually
protected workflow with publish=true and refresh_only=true for the same qualified
commit; this refreshes metadata and verifies HTTPS without attempting to recreate
v0.2.0. Candidate preparation uses publish=false. Refresh has NOT TESTED status
until run remotely. Never disable freshness checks to work around expiration.

Keep pool files immutable and retain older published packages for cached indexes
and rollback. The builder accepts multiple package inputs; operators must stage
all retained packages when preparing a future revision. The current first-release
workflow publishes the current package only; automatic retention across future
revision changes is not implemented. Archive the prior signed repository and
checksums before replacing it. Do not claim APT upgrade qualification until the
real previous→new revision transaction has run on both supported systems.

On a clean supported VM, record apt update logs, apt-cache policy cyberrecon,
dpkg -s cyberrecon, ownership, CLI/Doctor and installation dependency resolution.
Test targeted `sudo apt upgrade cyberrecon`, remove, reinstall and purge; verify
user DB/history/reports survive and package payload/bytecode is removed. Removal
of user data is separate: after explicitly deciding to discard it, the user may
manually remove the chosen CyberRecon workspace; package hooks never do this.

Troubleshooting: NO_PUBKEY means independently recheck/install the correct public
key; BADSIG or hash mismatch means stop and investigate/re-fetch trusted metadata.
An expired Release requires operator re-signing; certificate failures require
correcting HTTPS/clock trust, not bypassing TLS. No candidate may mean the wrong
source/component/architecture, missing indexes or unsupported distro dependencies.
Do not use trusted=yes, allow-unauthenticated, apt-key or disable signature checks.

Public key rotation/revocation requires publishing the new fingerprint via an
independent trusted channel, overlapping valid keys and requalifying trust before
retiring old keys. On compromise halt publication, revoke affected keys, publish
an incident notice independently and recover with an offline backup/primary key
and a fresh protected signing subkey. Do not restore or reuse a compromised key.
Revalidate the complete repository and both clean installs before resuming.

## First publication bootstrap

The production promotion gate intentionally requires real HTTPS/default-APT
qualification before it can publish the v0.2.0 release. It does not waive that
requirement for a first deployment. An administrator must first provision a
reviewed signed candidate on the actual HTTPS host using a separately controlled
signing/hosting environment, without declaring production readiness or creating
the production tag. Only public repository files are uploaded. Then run the clean
Kali/Parrot install/lifecycle checks against that host, review the exact-commit
evidence and enable the protected promotion workflow. The source scripts below
are administrator build steps, never requirements for end-user installation:

```bash
python3 scripts/build-cyberrecon-deb.py --production --maintainer "$CYBERRECON_MAINTAINER" --worker dist/candidate/cyberrecon-dns --output dist/candidate
# Protected environment supplies signing secrets; never paste them into commands.
python3 scripts/sign_cyberrecon_release.py dist/candidate/cyberrecon_0.2.0-5_amd64.deb --output dist/bootstrap-apt
python3 scripts/verify_cyberrecon_apt.py dist/bootstrap-apt --keyring dist/bootstrap-apt/cyberrecon-archive-keyring.gpg --fingerprint "$APT_SIGNING_FINGERPRINT" --production
```

Provisioning that host and configuring the existing owner-controlled key in GitHub
are BLOCKED in this session. The prepared workflow is
not an automatically executable bootstrap bypass. Installation will always need
one-time source/key setup unless the package is independently accepted into an
OS's official repositories; no such inclusion is claimed.


## Owner-supplied production identity and environment setup

Public expected fingerprint: `F1C454E3BB40C77AB236828DCB222DFEAD382DFC`.
Owner-supplied identity: `Thatikonda Naresh Goud <nareshthatikonda143@gmail.com>`.
Owner-supplied algorithm: Ed25519. These are public configuration, not secret
material. The actual production key was not imported or inspected in this session.
Do not replace it or use any historical development fingerprint as a production
trust anchor. Existing test fixtures remain separate development-only tests.

The owner must create/configure Settings → Environments → **cyberrecon-production**:

| Setting | Type | Value/action |
| --- | --- | --- |
| APT_SIGNING_FINGERPRINT | Environment variable; public | F1C454E3BB40C77AB236828DCB222DFEAD382DFC |
| CYBERRECON_MAINTAINER | Public variable | Thatikonda Naresh Goud <nareshthatikonda143@gmail.com> |
| APT_PUBLIC_URL | Public variable | Actual qualified HTTPS repository URL; not available here |
| RELEASE_QUALIFIED_COMMIT | Public variable | Exact independently qualified commit |
| RELEASE_QUALIFICATION_JSON | Reviewed evidence variable | Approved, clean, matching commit/version and every mandatory gate PASS |
| APT_SIGNING_PRIVATE_KEY | Environment secret | Owner adds encrypted private signing material privately in GitHub Settings |
| APT_SIGNING_PASSPHRASE | Environment secret | Owner adds its passphrase privately in GitHub Settings |

Never put the two secret values in source, .env, logs, artifacts, issues, commits
or this chat. No secret values are supplied or requested here. Require reviewers,
prevent self/bypass approval where supported and restrict deployment to main,
the existing workflow's intended ref. Audit all workflows allowed to use this
environment; GitHub Environment secrets are not inherently tied to a single
workflow file. Protect main and require review of release workflow changes.
Keep unrelated workflows outside the production environment. Separately protect
github-pages and configure candidate preparation without production secrets.

Sign and publish jobs explicitly reference environment.name cyberrecon-production.
Only the signing step receives the two secrets. It sets umask077, imports through
stdin into an isolated0700 GNUPGHOME, keeps its passphrase file0600, removes
secrets from child environments and suppresses import output. It independently
lists imported secret-key metadata and checks normalized fingerprint, approved
primary, exact public identity, Ed25519, validity and usable signing capability
before signing. Extra primary keys and a wrong/missing configured fingerprint fail.
Whitespace/case normalization is used for both key checks and signature pins.

Python finally cleanup restores environment/umask and removes temporary material.
A separate workflow **if: always()** step kills only temporary signing agents and
removes only matching temporary directories outside the workspace before uploads.
No set-x tracing is used. The local APT verifier checks both signatures against
the approved production primary/signing identity; all previous publication,
exact-commit, clean-tree, HTTPS and qualification gates remain in place.

On the owner's machine, validate public metadata without exposing private contents:

```bash
PRODUCTION_FP=F1C454E3BB40C77AB236828DCB222DFEAD382DFC
gpg --fingerprint "$PRODUCTION_FP"
gpg --batch --with-colons --with-fingerprint --with-subkey-fingerprint --list-keys "$PRODUCTION_FP"
```

Confirm the full primary fingerprint, supplied UID, Ed25519 and signing capability;
check expiry/revocation. These commands show public metadata only. If the key is
absent or differs, stop; do not generate a replacement or switch to a development
key. Populate only public variables and protected secrets through the owner UI.
After protected signing, use verify_cyberrecon_apt.py --production with this pin.
Actual production signing/secret installation/Environment protection, hosted HTTPS
and clean Kali/Parrot lifecycle remain NOT TESTED or BLOCKED. Local mock tests
cannot prove that the owner's real key/secrets are configured or usable.


## Protected signing dry-run

After reviewing/merging the workflow changes, manually dispatch **CyberRecon
protected APT release** on main with `signing_dry_run=true`, `publish=false`,
`refresh_only=false`. Selecting signing dry-run and publication together fails.
Both preparation and signing use cyberrecon-production approval; the package
requires the owner-supplied public maintainer identity. Configure the existing
fingerprint variable and the two secrets only in that Environment. Repository-level
duplicate signing secrets are neither needed nor permitted; the owner must check
Settings because workflow code cannot determine a secret's scope at runtime.

This mode builds the package, generates metadata, imports and independently checks
the existing production key, signs, verifies both signatures and the index/package
hash chain, then rejects altered disposable repository copies. The full preparation
suite also checks a different disposable signing key. Python/workflow cleanup runs
on failure. Secrets are removed from Python's environment immediately and unset
in the shell before verification/scanning subprocesses. Public signed artifacts
are retained for review; neither Pages upload/deployment nor GitHub Release creation
runs. The signing job retains only contents: read permission.

A successful real dry-run is evidence for production signing only. Publication still
requires exact-commit qualification, reviewed clean-tree evidence, HTTPS hosting
and every existing release gate. The dry-run has not been executed on GitHub here.
See [final signing security review](APT_SIGNING_SECURITY_REVIEW.md).


## Verified production signing milestone (2026-10-08)

[Run37639197830](https://github.com/naresh1807/CyberIntel/actions/runs/37639197830)
completed on commit1eb2eb937a743cc66f1c4e71ed6c34f5fdeeccb8: prepare/sign PASS,
cleanup PASS, Pages upload/deploy/publish SKIPPED. The protected production key
and fingerprint checks succeeded; no public repository or release was published.
Earlier NOT TESTED statements describe the earlier sessions. Independent raw-log
and signed-artifact inspection here remain NOT EXECUTED (authentication required).
Current local Node24 action updates require a fresh protected signing dry-run.
No installed OS/HTTPS lifecycle gate is implied by successful signing.
