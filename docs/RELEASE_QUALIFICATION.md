# Kali and Parrot release qualification

Baseline: c90c680. This phase changes packaging and qualification checks, not
the scanner architecture. CyberIntel, its entry point and its data remain intact.
The minimal package path passes isolated qualification; a full public release
is still gated on desktop VMs, default-APT validation and release identity.

## Source-verified release state

| Item | Verified value |
| --- | --- |
| CyberRecon / Go protocol | 0.2.0 |
| Debian package | cyberrecon 0.2.0-4; `all` without Go, build-host architecture with Go |
| Python distribution / compatibility desktop | cyberintel-suite / CyberIntel 0.1.0 |
| Console entry points | cyberrecon → cyberrecon.cli:main; cyberintel → cyberintel.app:main |
| Primary module | python -m cyberrecon |
| Debian launcher | /usr/bin/cyberrecon using /usr/bin/python3 and /usr/share/cyberrecon |
| Default state | ~/.local/share/cyberrecon/cyberrecon.db; SQLite schema 3 |
| State override | --home, then CYBERRECON_HOME, then default user home |
| Baseline / new source test count | 386 / 391 |

The Debian package includes the five required CyberIntel shared modules and
package initializer, not the compatibility GUI. The source installation retains
both complete applications. Neither command replaces the other.

## Python policy

- Minimum: Python 3.12. Metadata, Debian dependency, installer and Doctor agree.
- Recommended: the distro-provided Python 3.13 or 3.14; do not replace system
  Python to install this package.
- Tested here: 3.13.5 on Parrot and 3.14.7 on Kali. Full source suite ran on
  3.14.7; the CyberRecon subset ran on both distribution interpreters.
- Python <3.12 is unsupported. Python 3.12 is a declared minimum and CI target,
  but was not executed locally in this phase. Future Python versions remain
  unqualified until tested; metadata does not impose an arbitrary upper bound.

The source CI now has a 3.12/3.13/3.14 matrix. Configuring a job is not evidence
that it ran. No Python requirement was raised during qualification.

## Runtime dependencies

Debian uses distro packages, never pip in maintainer hooks. Direct requirements:
Python >=3.12, httpx >=0.28, dnspython >=2.7, PySide6 QtWidgets >=6.8,
NetworkX >=3.2.1, NumPy >=2.0 (Debian epoch `1:`), Plotly >=5.20 and
ReportLab >=4.3. Qt dependencies are resolved by the distro packages. Nmap is
recommended and required by the qualification fixture; other optional engines
are not required for native scans. Doctor now includes NumPy.

The full source distribution additionally requires cryptography, pandas,
pyqtgraph, folium, openpyxl and phonenumbers for compatibility modules. It keeps
the existing upper bounds. Those are not all CyberRecon Debian runtime needs.

Measured distro differences:

| Dependency | Kali 2026.3 rolling | Parrot Security 7.4 echo |
| --- | --- | --- |
| Python | 3.14.7 | 3.13.5 |
| httpx | 0.28.1 | 0.28.1 |
| dnspython | 2.8.0 | 2.7.0 |
| PySide6 | 6.10.3 | 6.8.2.1 |
| NetworkX | 3.4.2 | 3.2.1 |
| NumPy | 2.4.6 | 2.2.4 |
| Plotly | 5.20.0 | 5.20.0 |
| ReportLab | 5.0.0 | 4.3.1 |

## Actual environment and results

Official amd64 image filesystems were downloaded with verified layer SHA-256s:

- kalilinux/kali-rolling:
  `sha256:52b0d1581162a9fe506450b83055647e9a03e86672cc589467b235b69f585699`
- parrotsec/core:
  `sha256:7ac3f98c41fd0adf68a3c8ee2b3b69cc4c26335e8df3125b0c33a3928c08a7e2`

Image provenance: [Kali's official containers](https://www.kali.org/docs/containers/official-kalilinux-docker-images/)
and [Parrot's official containers](https://www.parrotsec.org/docs/containers/parrot-on-docker/).

Bubblewrap used private writable root filesystems and user/PID/IPC/UTS namespaces;
no overlay mounts or host APT installations were needed. Kernel is shared with
the host: Linux 7.1.5+kali-amd64 x86_64. Network was shared for distro downloads
and the script-owned 127.0.0.1 fixture. This is clean image filesystem testing,
not a fresh VM kernel or graphical desktop certification. APT used namespace
root as its sandbox user because a single-UID namespace cannot switch to _apt;
ownership warnings were retained. Real root-owned host package permissions
and multi-user isolation are not proven by that mapping.

| Check | Kali | Parrot |
| --- | --- | --- |
| Real dpkg install and apt dependency repair | PASS | PASS |
| Fresh image, minimal dependency repair (`--no-install-recommends`) | PASS | PASS |
| 0.2.0-3 → 0.2.0-4 upgrade | PASS | PASS |
| CLI version/help, Doctor core dependency checks | PASS | PASS |
| Non-root namespace UID 1000 CLI/default home/offscreen GUI | PASS | PASS |
| Package ownership lookup and launcher mode 0755 | PASS | PASS |
| Workspace 0700, database 0600, schema/integrity | PASS | PASS |
| Existing project, scan, observation and scope history preservation | PASS | PASS |
| Installed GUI startup/event-loop shutdown, offscreen | PASS | PASS |
| Installed TLS/Nmap local scan and report generation | PASS | PASS |
| Separate remove, reinstall/purge, fresh install/purge | PASS | PASS |
| User marker/database retained; installed payload/bytecode removed | PASS | PASS |
| CyberRecon source regressions with distro dependencies | 127 passed, 1 skipped | 127 passed, 1 skipped |
| Real desktop session / full Security edition VM | NOT TESTED | NOT TESTED |
| Fresh image, default APT recommendations | BLOCKED by namespace UID limit | STOPPED; not qualified |

The intentional skip is the regression that refuses an unmarked production
host: these disposable roots are explicitly marked for lifecycle changes.
The full source suite passed 391 tests, zero failures/skips, on the existing
Kali virtual environment. Go was unchanged in this phase; its earlier race
tests are historical evidence, not newly executed tests.

The first complete lifecycle runs installed runtime dependencies explicitly
before dpkg/APT verification. A separate fresh-image default-recommendations
attempt exposed a test-environment limit: Kali pulled systemd whose postinst
needs additional mapped UIDs and failed with fchownat/exit 73. The corresponding
Parrot default-recommendations attempt was stopped before qualification to
avoid the same unsupported single-UID environment. This is not evidence of a
CyberRecon defect, nor a successful default cold APT installation. Passwordless
sudo and multi-UID mapping helpers are unavailable; the production host was
not changed. The minimal dependency path is tested separately using
`apt-get install -f --no-install-recommends`. A normal privileged container/VM
is still needed to qualify the full default recommendation closure.

The fresh minimal runs began with fixture prerequisites only; dpkg reported
unresolved application dependencies, APT installed them, and the upgrade
installed the newly declared NumPy dependency. Parrot's OCI deletion markers
for APT caches were applied before this extraction. This is the clean-image
installation evidence; prepared-root runs are additional regression evidence.

Each installed lab run verified certificate/hostname validation, four HTTP
responses, one real open Nmap TCP port, two API observations and one JavaScript
file. JSON, CSV, HTML, PDF and directed graph files were nonempty. The target
was created and owned by the script; no third-party active target was scanned.
`--package` asserts imports come from /usr/share/cyberrecon, and `--require-nmap`
prevents a missing scanner from becoming an apparent success.

Configuration is intentionally the workspace, saved scopes/settings and
environment-only provider keys. There is no separate CyberRecon config.json,
/etc configuration or dedicated log directory to certify. Structured scan
warnings/errors and private evidence live in SQLite and per-scan JSON; terminal
diagnostics are captured by qualification. Doctor does not create a database.
The lifecycle user marker is a preservation fixture, not an app config file.

## Failures found and fixed

1. Debian omitted NumPy. `--no-install-recommends` installed successfully but
   graph reports failed with ModuleNotFoundError. NumPy is now a direct dependency.
2. Declared Plotly >=6 and NetworkX >=3.4 disagreed with supported distro
   repositories. Installed GUI/local scan/report/graph checks passed with
   Plotly 5.20 and Parrot's NetworkX 3.2.1. Metadata and Doctor now match those
   measured minima; Doctor checks patch versions where needed.
3. Root imports created package bytecode that dpkg alone left behind. A bounded
   prerm hook invokes Debian's `py3clean -p cyberrecon` before remove/upgrade.
   It does not remove user workspaces or install packages.

Harness corrections are separate from product bugs: rootless APT needs the
explicit sandbox-user setting; purge must be tested after reinstall because
this package has no conffiles and is forgotten after remove.

## Installation and reproduction

Build and install a local development package:

```sh
python3 scripts/build-cyberrecon-deb.py
sudo dpkg -i ./dist/cyberrecon_0.2.0-4_all.deb
sudo apt-get install -f
cyberrecon --version
cyberrecon --help
cyberrecon --doctor
cyberrecon
```

The commands above describe the normal user installation path; fresh default
APT recommendations remain a VM/container release gate. For the separately
tested minimal path use `sudo apt-get install -f --no-install-recommends`, or
`sudo apt install --no-install-recommends ./dist/cyberrecon_0.2.0-4_all.deb`.
Install Nmap separately if explicit-IP port scanning is needed.

APT can resolve a local package in one step instead:
`sudo apt install ./dist/cyberrecon_0.2.0-4_all.deb`.
Remove with `sudo apt remove cyberrecon` or purge an installed package with
`sudo apt purge cyberrecon`. Both preserve user-owned workspaces.

Run the manual `Kali and Parrot release qualification` GitHub workflow to
reproduce tests in digest-pinned official containers. It builds revision 3 from
c90c680 and revision 4 from the checkout, then runs
scripts/qualify_cyberrecon_release.py. JSON/log/report artifacts are uploaded
even on failure. This workflow has been updated, not remotely executed here.
The lifecycle script refuses package changes unless root and explicitly inside
a disposable OS marked at /run/cyberrecon-disposable-root. Never mark a host
production system. Source tests and installed tests are separate.

Captured source-only JSON evidence is in docs/release-evidence; full logs and
synthetic lab reports are retained under artifacts/release-qualification.
Evidence includes archive hashes and failed/stopped attempts. It is excluded
from the Debian payload so archive hashes are not recursively embedded.

## Remaining release gates

The tested support targets are these exact Kali rolling and Parrot echo image
snapshots on amd64. Older Parrot releases, other architectures and Security
edition desktop images are unqualified; a name alone does not establish support.
Test actual Kali/Parrot desktop VMs as normal users, including display/session
libraries, launcher/menu behavior, real root package ownership, reboot,
upgrade/purge and non-root scans. Offscreen startup cannot prove these.

License and maintainer identity remain development placeholders. There is no
hosted production APT repository or persistent release signing trust root.
`sudo apt update; sudo apt install cyberrecon` without a local package path
must not be advertised as available. Finalize these gates before public release.
Previously documented DNS snapshot/cancellation and large GUI refresh limits
remain; optional external engines, paid providers and UDP were not qualified
by this phase. CyberIntel remains a required compatibility dependency.
