# CyberRecon APT release report

The candidate results below are historical; see the production identity update
below for the current signing configuration status.

CyberRecon Version: **0.2.0**

Debian Revision: **5** (`cyberrecon 0.2.0-5`)

Architecture: **amd64**

Repository: **PUBLIC APT HOSTING REQUIRED — no production URL available**

Distribution: **stable**

Component: **main**

OS targets: Kali Linux and Parrot Security amd64; clean public APT installs remain
unqualified. Other distributions and architectures are not advertised.

Source baseline: `c1cdeb473d3bbb7f8cdb5988d908e69634a68cc4` plus uncommitted APT changes.
The Python distribution/legacy desktop remain cyberintel-suite/CyberIntel0.1.0
intentionally; application and DNS worker remain0.2.0.

Package SHA256: `da0416f418cd09e6c7ee62dfb2b1333f2dfee2337ae61f25fc5417effe535138`

Package: dist/apt-production-phase/cyberrecon_0.2.0-5_amd64.deb (ignored artifact).
Package builder (with explicit SOURCE_DATE_EPOCH timestamp normalization),
ownership/mode checks, dpkg-deb --info/--contents and staged
launcher/storage verification passed. This is a development candidate with an
unconfigured maintainer, not a production-identity package. Build provenance is
in dist/apt-production-phase/build-manifest.json; SHA256SUMS covers public artifacts.
This report is excluded from the Debian payload to avoid embedding its own hash.

## APT metadata and signing

| Check | Result | Scope |
| --- | --- | --- |
| Release | PASS | Local apt-ftparchive output; SHA256 index hashes/dates/architecture |
| InRelease | PASS | Actual gpgv signature, pinned signer, exact payload comparison |
| Release.gpg | PASS | Actual detached signature verification |
| Packages | PASS | Control fields, versions, paths, sizes and package SHA256 |
| Packages.gz | PASS | Bounded decompression equals Packages |
| Private-key/artifact checks | PASS | Bounded heuristic scans and private-key regression |
| Production signing | BLOCKED | PRODUCTION SIGNING KEY REQUIRED |
| Production public fingerprint | BLOCKED | No operator key provisioned; no value invented |
| HTTPS/public installation | BLOCKED | Public HTTPS hosting is not configured |
| Remote Actions/Pages workflow | NOT TESTED | No authenticated deployment performed |

**Development-only fingerprint:** `9A0A07DA92FEBAADDAC19A94FB46922D34735C79`.
The disposable private test key was removed after signing; its public key is not
an end-user production trust anchor. Final local metadata is under
`dist/apt-production-phase/normalized-repository/`. Production signing remains separate
through protected secrets and temporary0700 GNUPGHOME/passphrase0600 outside source.

## Executed tests and lifecycle

Full command: `.venv/bin/python -m pytest -q --junitxml artifacts/apt-production-phase/pytest.xml`.
**421 passed, 0 failed, 0 skipped, 0 xfailed** (35.091 seconds).
Eleven new cases exercise genuine GPG signatures, metadata/hash chains, tampering,
wrong fingerprints, development-publication rejection, private-key leakage,
real isolated apt-get update/candidate policy and unsigned-repository rejection.
The old revision4 resolver fixture uses revision5 code with synthetic metadata;
it does not prove an actual old→new application upgrade. No system source list,
keyring, database or package installation was changed by these tests.

| Required production check | Status | Reason |
| --- | --- | --- |
| Kali install | NOT TESTED | No clean privileged desktop VM |
| Parrot install | NOT TESTED | No suitable desktop VM |
| Upgrade | NOT TESTED | No hosted production repository or clean VM |
| Remove | NOT TESTED | No installed production APT package in clean VM |
| Reinstall | NOT TESTED | Same prerequisite missing |
| Purge | NOT TESTED | Same prerequisite missing; user state must be retained |
| End-user apt update / apt install cyberrecon | BLOCKED | Hosting, signing and qualification absent |

## Reused implementation and publication

Existing build-cyberrecon-deb.py, build-cyberrecon-apt.py, sign_cyberrecon_release.py,
prepare_cyberrecon_release.py and archive checks are reused. The existing workflow
is renamed to .github/workflows/release-apt.yml, with pre-publication signed-chain
verification and a manually protected refresh option. No duplicate publication
workflow exists. Pages remains the prepared static HTTPS host, not a live URL.
Refresh, first-host bootstrap and retention of previous immutable pool packages
are documented, with explicit limits. No release gates are bypassed.

## Remaining blockers and exact installation path

1. Real public maintainer identity and a protected production signing key/public
fingerprint must be provisioned; none is fabricated or committed.
2. An administrator must bootstrap the reviewed candidate at an actual HTTPS
host and distribute the verified public fingerprint independently.
3. Run clean Kali/Parrot public APT install/upgrade/remove/reinstall/purge tests;
review exact-commit evidence and protected workflow execution before approval.

The guarded [one-time key/source setup](APT_REPOSITORY.md) must complete first.
Then the intended end-user command is:

```bash
sudo apt update
sudo apt install cyberrecon
cyberrecon --version
cyberrecon --doctor
cyberrecon --help
```

These commands are **not currently verified against a production repository**.
No clone, Python script, manual .deb download or build is required for end users
once the real signed repository has been configured and qualified.

Production status: **NOT APPROVED**.

## Production identity update

The owner subsequently supplied public fingerprint
F1C454E3BB40C77AB236828DCB222DFEAD382DFC and
Thatikonda Naresh Goud <nareshthatikonda143@gmail.com> (Ed25519).
Historical development fingerprint/results above are not production trust.
Imported production-key checks and protected Environment cleanup are IMPLEMENTED.
Real production import/signing and Environment secrets/protections remain NOT TESTED.
Production status remains NOT APPROVED. See APT_REPOSITORY.md for manual owner setup.

Signing setup validation: complete suite **437 passed, 0 failed, 0 skipped**
(37.56 seconds), artifacts/production-signing-setup/pytest.xml. Workflow YAML
parsed, git diff --check passed, and the source security heuristic scan passed
for 150 files; tracked private-key header search found no matches. These are
bounded source checks, not proof of real production-secret configuration.
Production qualification with the supplied public maintainer identity failed
closed because the HTTPS APT hosting URL is missing.
Dedicated signing/APT/release regression run: **51 passed** (2.63 seconds),
including real development-only InRelease and Release.gpg verification.
Production-key signature verification remains **NOT TESTED**.

Final security review: [APT_SIGNING_SECURITY_REVIEW.md](APT_SIGNING_SECURITY_REVIEW.md).
451 Python tests and the Go race suite passed. Protected signing dry-run and
expanded tamper checks are implemented; real owner-key/GitHub/HTTPS/VM lifecycle
results remain NOT TESTED or BLOCKED. Production release remains NOT APPROVED.


## Verified signing run update (2026-10-08)

Public run37639197830, commit1eb2eb937a743cc66f1c4e71ed6c34f5fdeeccb8:
prepare/sign and cleanup PASS; Pages artifact upload, deploy and publish SKIPPED.
The production signing path, approved fingerprint and repository verification
succeeded. No public APT, GitHub Pages or GitHub Release publication occurred in
this run. Its logs/artifact download require authentication; independent inspection
here is NOT EXECUTED. Earlier non-execution/blocked signing entries are historical.
New action pins must be exercised by another protected nonpublishing dry-run.
Overall production decision remains NOT APPROVED pending installed-system gates.
