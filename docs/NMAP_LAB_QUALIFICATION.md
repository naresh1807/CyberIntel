# Local Nmap qualification diagnostics

Audit date: 2026-10-08 (America/New_York). No production release/publication.

The TCP adapter already uses -sT, -sV, --version-light, -n, -Pn, bounded retries,
timeouts, two probes/second and at most two parallel probes. Targets are explicit
scoped IP addresses, commands are fixed argument arrays without a shell, and XML
must report a successful scan with the expected address/port. Doctor's READY is
a version-family probe; it does not prove runtime network permissions.

## Measured reproduction

This section records the earlier image-root reproduction before the runner
reported exit 126. See the capability conflict investigation below for the new
reproduction and narrowly guarded environment fix.

The unchanged pinned Kali/Parrot image layers were SHA256 verified and extracted
into isolated bubblewrap roots. Nmap was installed through each distribution's
signed APT repositories. No host packages or CI capabilities were changed.
Parrot's slow redirect mirror was replaced only in the disposable reproduction
root with its officially listed direct mirror; the CI sources/images are unchanged.
The kernel/network are shared with the host; this is not GitHub's Docker/seccomp
runtime or a full distribution workflow run.

| Image | Binary/version | Effective UID/capabilities | Original command | Explicit unprivileged command |
| --- | --- | --- | --- | --- |
| Kali rolling (pinned52b0d158…) | /usr/bin/nmap7.99 | UID0, CapEff0 | exit0, owned TLS port OPEN, stderr empty | exit0, same owned TLS port OPEN, stderr empty |
| Parrot core (pinned7ac3f98c…) | /usr/bin/nmap7.95 | UID0, CapEff0 | exit0, owned TLS port OPEN, stderr empty | exit0, same owned TLS port OPEN, stderr empty |

Commands/output: artifacts/nmap-container-fix/tls-comparison.json. Both variants
used the same adapter-generated arguments and an ephemeral script-owned loopback
TLS server. No external target was scanned. The original reported tool_failed
could NOT be reproduced here, so its exact GitHub cause remains UNCONFIRMED.
Missing Nmap, bad arguments and a universally required raw capability were not
observed in these image-root reproductions. Do not label the remote failure fixed
or specifically raw-socket-related without new runner evidence.

## Local-only mitigation and diagnostic change

verify_cyberrecon_lab.py now explicitly requests --unprivileged with the existing
TCP-connect mode for its fixed owned127.0.0.1 fixture. [Nmap documents this option](https://nmap.org/book/man-misc-options.html)
as suppressing privileged/raw-socket assumptions. This is a least-privileged
lab choice, not a proven explanation of the original remote error. There is no
fallback to a mock, no fabricated OPEN result, no broad capability grant and no
production default scan-mode change. UDP rejects this TCP-only mode.

Only opted-in lab diagnostics print executable/version, effective UID, capability
fields, exact argv, actual exit code and stdout/stderr samples bounded to8192 bytes
per stream. Control characters are removed and JSON-escaped; environment variables,
key material and outside targets are not logged. Nonzero exits/timeouts still fail.
The existing output/time/cancellation/scope/XML checks remain. The distribution
workflow now requires real Nmap instead of permitting an absent binary fallback.

Executed local checks:
- Full Python suite:454 passed in56.47s, no skipped/failed tests.
- Three new diagnostics/explicit-mode regressions included in the full suite.
- Exact updated TLS lab: complete scan, HTTP4, ports1 (real OPEN), APIs2,
  JavaScript1, verified TLS, generated reports. Scan6645522b-4f01-41d2-bf3b-4e529997b08f.
- Go worker: uncached go test -race -count=1 ./... passed in1.014s.
- Workflow/static validation and bounded source credential scan passed.

## Required next runner evidence

Review/push the change, then run Kali and Parrot distribution qualification on
that exact commit. Confirm the real lab's process returncode0 and the snapshot's
owned server port OPEN in both jobs. If it still fails, inspect the newly printed
stderr/exit/capability diagnostics to identify the actual runner-specific cause.
No authenticated workflow dispatch or new GitHub success is claimed here.
Production publication, signing identity and pinned images/actions are unchanged.

## Exit 126: Kali file capabilities versus container bounding set

The subsequent runner error identifies an exec failure before Nmap processes
arguments: `/usr/bin/nmap: 6: exec: /usr/lib/nmap/nmap: Operation not permitted`.
The installed official Kali package's `nmap.postinst` assigns
`cap_net_raw,cap_net_admin,cap_net_bind_service+eip` to this ELF executable.
Linux rejects execution of an effective file-capability binary when its requested
permitted capabilities exceed the process bounding set. See the
[kernel capability rules](https://man7.org/linux/man-pages/man7/capabilities.7.html)
and [Kali's package issue](https://gitlab.com/kalilinux/packages/nmap/-/issues/7).
`--unprivileged` cannot fix this: the process never starts.

Reproduced using the actual installed Kali binary in an isolated user/mount/PID
namespace, with the package's file capabilities restored and only NET_ADMIN
removed from CapBnd. It produced the exact launcher stderr and exit 126.
AppArmor was unconfined, seccomp disabled, libraries resolved, permissions 0755,
and `dpkg --verify nmap` passed. Removing only the file capability attribute
allowed the identical binary, mounts and runtime to execute successfully. The
actual TLS lab then returned exit 0 and parsed the controlled loopback port OPEN.
Evidence: `artifacts/nmap-eperm/reproduction.log`. This reproduces the capability
mechanism, not GitHub's entire runtime; remote CapBnd/xattr evidence is still needed.

`scripts/qualify_nmap_runtime.py` now prints package integrity, relevant mounts,
AppArmor, seccomp, UID/capability state, file capabilities, permissions, library
resolution and the real version-probe exit/output before any change. It removes
the file capability attribute only when all of these conditions hold: a marked
disposable root, Kali, exit 126, and effective file capabilities outside CapBnd.
It verifies executable bytes remain unchanged and requires a successful real
version probe afterward. Other causes remain failures. Parrot has no capability
removal branch. Production package/application behavior and container capabilities
are unchanged; the real lab still requires `--unprivileged -sT` and actual OPEN XML.

Full desktop/reboot/package lifecycle and a successful exact-commit GitHub run
remain required. No publication or production signing change is authorized here.

Checks after this change: native Python suite 457 passed; pinned Kali filesystem
suite 456 passed with one existing disposable-root lifecycle-guard skip; offscreen
GUI startup and Go race tests passed. Real unprivileged TLS loopback Nmap runs
returned exit 0 and OPEN XML in both pinned Kali and Parrot filesystems. Three
capability/disposable-host guard regressions, workflow shell/pin/security checks
and the 160-file bounded credential scan passed. No test skip was introduced.
Public run [37746000518](https://github.com/naresh1807/CyberIntel/actions/runs/37746000518)
on cc76719 failed Kali source tests and Parrot package lifecycle qualification.
The latter failure is unresolved; no successful remote rerun is claimed.
