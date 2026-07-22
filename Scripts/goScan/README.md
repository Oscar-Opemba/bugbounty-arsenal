# goScan — Bounded TCP Connect Scanner

A small Go TCP connect scanner with a bounded worker pool, safe defaults, and a
size guard.

> ## ⚠️ Authorized use only
> Port scanning can disrupt fragile services and is unlawful without permission.
> Scan only hosts you are authorized to test. See [`../../LEGAL.md`](../../LEGAL.md).

## What changed from the original

The original never compiled (it called `net.IPToBigInt` / `net.BigIntToIP`,
which don't exist) and launched **one goroutine per port for all 65,535 ports
per host at once** — an unbounded connection storm. This version:

- **Compiles** (real IP-range/CIDR expansion via `net/netip`).
- **Bounds concurrency** with a worker pool (`-concurrency`, default 100).
- **Safe default port set** (`-ports top`) instead of all 65,535 — full coverage
  is still available (`-ports 1-65535`).
- **Size guard**: refuses more than `-max-connections` (default 50,000) unless
  `-yes`, so a fat-fingered `/16` can't fire millions of connections by accident.
- **Authorization confirmation** before scanning (skip with `-yes`).
- **Per-port timeout** (`-timeout`, default 3s).

## Build & run

```bash
cd Scripts/goScan
go build -o goscan .

# Scan common ports on your lab host (prompts for confirmation)
./goscan -targets 192.168.56.10 -ports top

# A range / CIDR, specific ports, non-interactive
./goscan -targets 192.168.56.0/24 -ports 22,80,443 -yes

# Full port range on one host
./goscan -targets 10.10.10.5 -ports 1-65535 -yes
```

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-targets` | — (required) | IPs, CIDRs, or IPv4 ranges (`a-b`), comma-separated |
| `-ports` | `top` | `top`, `1-1024`, `80,443`, or a mix |
| `-concurrency` | `100` | max simultaneous connections |
| `-timeout` | `3s` | per-port dial timeout |
| `-max-connections` | `50000` | refuse larger scans unless `-yes` |
| `-yes` | `false` | skip confirmation / size guard |

## Testing

```bash
go test ./...   # unit tests for port & target parsing (no network)
go vet ./...
gofmt -l .      # should print nothing
```

Only the pure parsing helpers are unit-tested; the actual `scan()` opens sockets
and should be exercised against a lab you control (e.g. `-targets 127.0.0.1`).
