# CyberRecon 0.2.0 — Debian revision 5 candidate

This candidate improves release safety and desktop packaging without changing
the scanner architecture or removing CyberIntel. It adds MIT licensing, an app
icon/About dialog, Doctor requirement guidance, normalized Debian permissions,
amd64-only APT publication, bounded artifact checks, pinned build tools/actions,
and a protected signing/publication workflow. The final gate additionally requires
reviewed exact-commit evidence for every mandatory gate, records build provenance
and preserves old-package owned-target scan state plus all report formats across
the disposable lifecycle harness. The production tag is v0.2.0 only after approval.

Python minimum remains 3.12; current full testing uses 3.14.7. Runtime/Go protocol
remain 0.2.0; compatibility distribution remains cyberintel-suite 0.1.0.
Development maintainer identity is intentionally unconfigured. Do not describe
this candidate as publicly installable or VM-qualified until the required gates
in PRODUCTION_RELEASE_READINESS.md and RELEASE_CHECKLIST.md have passed.

Current measurements: 410 Python tests in the final-gate phase,
Go race/build checks, actual normal-user Kali X11 source GUI, owned TLS/Nmap scan,
Debian staging, dependency re-audit and disposable development signatures.
Remaining: fresh Kali/Parrot desktop VMs, reboot, actual 4→5 install/upgrade/remove/
purge, installed menu/browser handoff, operator identity, production signing and
public default-APT validation. User data is preserved during package removal.
