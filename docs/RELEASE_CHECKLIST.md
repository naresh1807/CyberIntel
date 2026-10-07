# CyberRecon v0.2.0 final release checklist

Checked boxes apply only to the explicitly stated source/staging scope. Every
VM installation item remains unchecked until actually executed. Production is
NOT APPROVED; no v0.2.0 tag has been created.

## Build

- [x] Source tests pass (410; current working tree)
- [x] Debian package builds (development candidate)
- [x] Package contents validated (staging)
- [x] SHA256 generated (development candidate)

## Kali

- [ ] Fresh install (installed desktop VM)
- [ ] CLI (installed desktop VM)
- [ ] Doctor (installed desktop VM)
- [ ] GUI (installed desktop VM)
- [ ] Launcher (installed desktop VM)
- [ ] Non-root (installed desktop VM)
- [ ] Upgrade (installed desktop VM)
- [ ] Reboot (installed desktop VM)
- [ ] Remove (installed desktop VM)
- [ ] Purge (installed desktop VM)
- [ ] Reinstall (installed desktop VM)

## Parrot

- [ ] Fresh install (installed desktop VM)
- [ ] CLI (installed desktop VM)
- [ ] Doctor (installed desktop VM)
- [ ] GUI (installed desktop VM)
- [ ] Launcher (installed desktop VM)
- [ ] Non-root (installed desktop VM)
- [ ] Upgrade (installed desktop VM)
- [ ] Reboot (installed desktop VM)
- [ ] Remove (installed desktop VM)
- [ ] Purge (installed desktop VM)
- [ ] Reinstall (installed desktop VM)

## Security

- [x] Scope enforcement (regressions)
- [x] TLS (owned local target and regressions)
- [x] subprocess security (regressions/AST checks)
- [x] permissions (workspace/staging)
- [x] API-key handling (regressions; live credentials not tested)
- [x] package security (archive/ownership/mode checks)
- [ ] Installed VM package security and clean lifecycle

## Distribution

- [ ] Production APT
- [ ] HTTPS repository verification
- [ ] Repository signing with production trust anchor
- [ ] GitHub release / v0.2.0 tag
- [x] checksums (development candidate)
- [x] installation docs (explicitly gated)

## Project

- [x] LICENSE (MIT)
- [ ] Maintainer metadata
- [x] README (primary CyberRecon/legacy boundary)
- [x] Responsible-use policy
- [x] Known limitations


# Release checklist and exact candidate commands

No production sign-off until every required VM/identity/hosting gate is recorded
against the exact commit. A reviewer must assess the evidence. Production requires a matching reviewed
RELEASE_QUALIFICATION_JSON with every gate PASS and decision APPROVED, not just
a SHA variable. This remains an attestation, not automatic desktop proof.

## Clean candidate build

On a disposable amd64 build environment with Python 3.14, Go 1.26.8,
apt-utils/dpkg-dev, GnuPG, desktop-file-utils, Nmap and Qt runtime libraries:

```bash
git clone https://github.com/naresh1807/CyberIntel.git
cd CyberIntel
git checkout <EXACT_REVIEWED_COMMIT>
python3.14 -m venv .venv
.venv/bin/python -m pip install -r release/tools.txt
.venv/bin/python -m pip install -c release/constraints-python314.txt -e '.[dev]'
.venv/bin/python -m pytest -q
.venv/bin/python scripts/verify_cyberrecon_startup.py
.venv/bin/python scripts/verify_cyberrecon_lab.py --tls --require-nmap --home artifacts/clean-release-lab
.venv/bin/python -m pip_audit --no-deps --disable-pip -r release/constraints-python314.txt
mkdir -p dist/candidate
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
(cd workers/dns && go test -race ./... && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o ../../dist/candidate/cyberrecon-dns .)
.venv/bin/python -m build --no-isolation --outdir dist/candidate
# Development candidate; production requires --production --maintainer with a real identity.
python3 scripts/build-cyberrecon-deb.py --worker dist/candidate/cyberrecon-dns --output dist/candidate
.venv/bin/python scripts/verify_cyberrecon_package.py dist/candidate/cyberrecon_0.2.0-5_amd64.deb
python3 scripts/check_release_security.py --artifacts dist/candidate
.venv/bin/python scripts/prepare_cyberrecon_release.py --build-manifest dist/candidate
python3 scripts/prepare_cyberrecon_release.py --checksums dist/candidate
(cd dist/candidate && sha256sum -c SHA256SUMS)
```

Do not replace distribution Python on either target. Python 3.14 build constraints
are for the source candidate, not the distribution package dependency resolver.
Follow [APT operations](APT_REPOSITORY.md) for gated publication.

## Both fresh desktop VMs: required manual qualification

Take a VM snapshot and record OS ISO provenance, commit and package SHA256. Keep
Kali and Parrot reports separate. Use a normal desktop user; sudo only for package
transactions. Record Python, kernel, desktop, package resolver and dependency data.

```bash
python3 --version
uname -a
cat /etc/os-release
printf '%s
' "$XDG_CURRENT_DESKTOP" "$XDG_SESSION_TYPE"
id
sudo dpkg -i ./cyberrecon_0.2.0-4_all.deb
sudo apt-get install -f
cyberrecon --version
cyberrecon --help
cyberrecon --doctor
cyberrecon
```

Use the application menu and terminal separately. Verify icon, readable theme,
window scaling, tab navigation, scope errors, scan progress/cancellation and a
script-owned local TLS target. Run installed lab verifier (`--package --tls
--require-nmap`) from the checkout as the normal user. Export PDF/CSV/HTML/JSON
and graph, open them, record hashes, DB integrity, project/scope/scan counts and
permissions. State defaults to ~/.local/share/cyberrecon, schema 3; directory0700,
DB0600. Logs/reports remain user-owned. Test isolated --home first; no real targets.

Close the app and reboot the disposable VM. Reopen, compare scope/history/data
and report hashes. This step has NOT run on the user's host. Snapshot evidence.

```bash
sudo dpkg -i ./cyberrecon_0.2.0-5_amd64.deb
sudo apt-get install -f
cyberrecon --version
cyberrecon --doctor
dpkg-query -W cyberrecon
dpkg-query -L cyberrecon
```

Repeat GUI/local scan checks after upgrade and after another VM reboot. Verify
unchanged historical data/export hashes and no orphan launcher or worker.

```bash
sudo apt remove cyberrecon
command -v cyberrecon || true
sudo apt purge cyberrecon
```

Verify /usr/bin launcher/worker and desktop/icon/package directories are removed;
verify user's DB, projects and exports still exist and pass integrity/hash checks.
Removal must not delete user data. Reinstall and confirm the same workspace opens.
Manual deletion of user state is a separate explicit user action, never an install
hook. Then validate public signed HTTPS APT setup with default authentication,
install/upgrade/remove/purge and rejection of tampered/expired metadata in the
VM. Do not run default-APT production claims against a development key.

Required sign-off: both desktop VMs, reboot persistence, exact-commit 4→5 lifecycle,
public maintainer/license review, dependencies, independent public fingerprint,
HTTPS reachability, default APT trust, protected environments/secrets, artifact
checksums, release notes and rollback/rotation plan. Record failures as BLOCKED
or NOT TESTED, not PASS. Do not use a container result as desktop proof.
