# Go DNS worker protocol

Build with Go 1.22+ (no external modules):

```sh
cd workers/dns
go test -race ./...
go build -trimpath -o ../../dist/cyberrecon-dns .
```

The Python orchestrator supplies one JSON job on stdin, bounded to 1 MiB and 30 hosts. Fields: `id`, `hosts`, canonical `include`/`exclude` scope lists, `concurrency` (1–8). Stdout is NDJSON, one result per input host: `id`, `host`, `addresses`, optional `error`. No arbitrary commands, request URLs, scripts or engine flags are accepted. Exit 1 means the job is invalid or output failed. Exclusions override includes; a wildcard does not include its apex. Internet-wide CIDRs are rejected.

Work uses up to eight goroutines, a three-second resolution deadline and a global maximum of two host dispatches per second. Python supervises cancellation, process duration and output size. Scope is a snapshot per bounded job; edit scope and cancel/restart a running worker to apply changes before its subsequent DNS lookups. Resolved IPs are observations, not automatic permission for port scanning.
