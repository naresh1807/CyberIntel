# CyberRecon

**Version 0.2.0** — authorized bug-bounty reconnaissance for owned infrastructure
and explicitly permitted targets. **Production release: NOT APPROVED.**
**Production APT repository: pending publication — NOT YET AVAILABLE.**

Primary supported OS targets: **Kali Linux** and **Parrot Security**.
Initial architecture: **amd64**. These are intended release targets; fresh desktop
VM qualification is incomplete. Live Kali 2026.3 source GUI testing exists;
Parrot desktop, installed menu, reboot and revision-5 package lifecycle remain
blocked or untested. See the [release decision](docs/PRODUCTION_RELEASE_READINESS.md).

## Installation

Python minimum: 3.12; use the distribution's supported Python 3.13/3.14 when
available. Do not replace system Python. Build a development Debian candidate:

```bash
python3 scripts/build-cyberrecon-deb.py
# Install only on your disposable qualification VM until release gates pass:
sudo apt install ./dist/cyberrecon_0.2.0-5_all.deb
cyberrecon --version
cyberrecon --help
cyberrecon --doctor
cyberrecon
```

The optional compiled Go DNS worker produces an amd64 package when passed with
`--worker`; the worker's protocol remains 0.2.0. Production builds require a real
public maintainer identity through `--production --maintainer 'Name <email>'`.
The development identity is intentionally unconfigured. Public default-APT
installation is unavailable; [APT setup](docs/APT_REPOSITORY.md) is a future
operator template, not a live installation source.

For source development with Qt runtime libraries already installed:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m cyberrecon --doctor
.venv/bin/python -m cyberrecon
```

## CLI, GUI and authorized scope

`cyberrecon` without a subcommand launches the GUI as a normal desktop user.
Navigation uses tabs. Enter include/exclude rules, an authorization reference
and an owned target before starting a scan. Saved scopes/history are retained.
Doctor reports required Python dependencies and optional tool capabilities;
missing integrations remain unavailable rather than producing synthetic results.

The CLI supports projects, scoped scans, history, comparison and exports. Example
for a service you own on loopback (substitute the actual port and returned IDs):

```bash
cyberrecon project 'Owned local lab' --include 127.0.0.1 --authority 'I own this local service'
cyberrecon scan http://127.0.0.1:8080 --project <PROJECT_ID> --crawl
cyberrecon scans <PROJECT_ID>
cyberrecon export <SCAN_ID> ./reports/local-lab
```

## Reports and storage

Exports include JSON, CSV, HTML, PDF and an interactive graph. The GUI offers
Export reports and Open graph; external browser handoff is not currently
qualified. State defaults to `~/.local/share/cyberrecon/` (directory 0700,
database 0600, SQLite schema 3). `--home` or `CYBERRECON_HOME` selects an isolated
workspace. Settings/scopes and structured errors live in the workspace; there
is no separate config.json or dedicated log service. Provider keys are supplied
through environment variables and are not saved in CyberRecon settings.

## Upgrade and uninstall

On a disposable VM, install revision 4, create an owned-target scan and export
reports, then install the revision-5 candidate:

```bash
sudo apt install ./dist/cyberrecon_0.2.0-5_all.deb
cyberrecon --doctor
sudo apt remove cyberrecon
# To test purge independently, reinstall first (there are no package conffiles):
sudo apt install ./dist/cyberrecon_0.2.0-5_all.deb
sudo apt purge cyberrecon
```

Remove/purge are designed to preserve user databases, scopes, history and reports.
Do not silently delete user state. Actual revision-5 upgrade/remove/purge/reinstall
and reboot must still be executed on both desktop VMs; staged extraction is not
package transaction evidence. Follow the [exact checklist](docs/RELEASE_CHECKLIST.md).

## Security model and limitations

Include/exclude scope, wildcard and IP/CIDR checks precede active operations;
private destinations require explicit IP authorization. HTTP uses verified TLS,
validated/pinned destinations, scoped redirects, bounded requests/responses and
redacted parameter values. Subprocesses use fixed argument arrays without shells,
with time/output limits. Reports escape untrusted data and protect CSV cells.
Operate only within explicit authorization; the platform provides observations
and review candidates, not proof of exploitation or exhaustive discovery.

Tables cap displayed rows at 1000 and graphs at 300 nodes. Refresh is synchronous;
large datasets can pause the GUI. Dashboard/settings/Doctor contain text/JSON
panels, not rich dedicated dashboards. A sidebar is not implemented. Optional
engines, paid providers, UDP, authenticated API assessment and broad external
coverage are not certified by the owned local lab. No credential theft, private
CDR lookup or arbitrary exploitation workflow is part of this release.

## License and compatibility

[MIT](LICENSE) applies to this project. Public maintainer name/email is still a
release blocker. CyberRecon/Go protocol are 0.2.0; `cyberintel-suite` and the
independent CyberIntel compatibility desktop remain 0.1.0. The `cyberintel/`
package and command are retained. [Legacy usage](docs/CYBERINTEL_USAGE.md) and the
[future migration plan](docs/COMPATIBILITY_MIGRATION.md) describe that boundary.

See [CyberRecon usage](CYBERRECON.md), [security audit](docs/AUDIT.md),
[architecture audit](docs/ARCHITECTURE_AUDIT.md),
[historical package qualification](docs/RELEASE_QUALIFICATION.md), and
[production signing operations](docs/APT_REPOSITORY.md).
