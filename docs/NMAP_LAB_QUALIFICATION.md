# Local Nmap qualification diagnostics

Audit date: 2026-10-08 (America/New_York). No production release/publication.

The TCP adapter already uses -sT, -sV, --version-light, -n, -Pn, bounded retries,
timeouts, two probes/second and at most two parallel probes. Targets are explicit
scoped IP addresses, commands are fixed argument arrays without a shell, and XML
must report a successful scan with the expected address/port. Doctor's READY is
a version-family probe; it does not prove runtime network permissions.

## Measured reproduction

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
