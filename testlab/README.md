# xmap Top-30 protocol lab

This is a Linux-only, isolated Docker bridge network for reproducible service
fingerprinting tests. No service port is published to the host. The test runner
on a Linux host reaches the fixed addresses directly through the bridge.

`compose.yaml` provisions all 30 entries from `top30.json`:

- Real services: HTTP, Redis, PostgreSQL, MySQL and SMB.
- `simulators` container: the other TCP, TLS and UDP protocol fixtures.

The simulator uses one fixed address (`172.28.0.20`) and standard service ports.
The separate IP prevents conflicts with real services, while standard ports make
xmap select the same port-aware probes it uses in production. The complete
authoritative mapping is in `targets.json`; it is intentionally consumed by the
report rather than duplicated in scripts.

## Run on Linux

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -o testlab/bin/testlab-simulators ./cmd/testlab-simulators
docker compose -f testlab/compose.yaml up -d --build --wait
mkdir -p reports
go run ./cmd/testlab-report reports/testlab-report.md
docker compose -f testlab/compose.yaml down -v
```

The report is intentionally a gate: it exits non-zero when any provisioned
target is not identified as its expected protocol. A reachable target therefore
does not artificially inflate coverage. The GitHub tag workflow performs the
same steps and always uploads the generated report as an artifact.

## Current baseline

All 30 targets are provisioned and were connection-tested inside the Docker
network. The current scanner baseline is 15/30 recognitions. The remaining
failures are regression work for service probes (not missing test services),
notably TLS-wrapped mail/FTP protocols, DNS, Redis, MongoDB, VNC, Memcached and
service-name aliases such as RDP (`ms-wbt-server`).
