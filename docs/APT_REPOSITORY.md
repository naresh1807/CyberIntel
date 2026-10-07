# APT repository and signing operations

**Production status: BLOCKED.** No public HTTPS URL or maintainer identity is
available. `sudo apt install cyberrecon` from the default Kali/Parrot repositories
is not supported today. GitHub Pages is a prepared hosting option, not a live
repository. Only local development signing has been executed.

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

`.github/workflows/production-release.yml` is manual, main-only, and defaults to
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
gh workflow run production-release.yml --ref main -f publish=false
# Review the prepared artifacts and run both desktop VM checklists.
# Set RELEASE_QUALIFIED_COMMIT to that exact main commit, then:
gh workflow run production-release.yml --ref main -f publish=true
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
APT_BASE='<YOUR_APT_HTTPS_URL>'
curl --fail --proto '=https' --tlsv1.2 "$APT_BASE/cyberrecon-archive-keyring.gpg" -o cyberrecon-archive-keyring.gpg
gpg --show-keys --with-fingerprint cyberrecon-archive-keyring.gpg
# Stop here until the fingerprint has been verified independently.
sudo install -m 0644 cyberrecon-archive-keyring.gpg /usr/share/keyrings/cyberrecon-archive-keyring.gpg
printf 'deb [arch=amd64 signed-by=/usr/share/keyrings/cyberrecon-archive-keyring.gpg] %s stable main
' "$APT_BASE" | sudo tee /etc/apt/sources.list.d/cyberrecon.list
sudo apt update
apt-cache policy cyberrecon
sudo apt install cyberrecon
cyberrecon --version
cyberrecon --doctor
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
