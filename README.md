# Spip - Network Honeypot Sensor

Spip is a lightweight, low-interaction network honeypot sensor. It listens for arbitrary incoming TCP traffic (plain and TLS), captures what scanners and bots send, and logs each connection as structured JSON (ECS-shaped) for easy ingestion into your SIEM or data lake.

## Quick Start

**Prerequisites**
- Go 1.24.0 or later
- Linux with `iptables`
- Root access (required to apply the example iptables rules)

1) Build the agent
```bash
git clone https://github.com/StefanGrimminck/Spip-Go.git
cd Spip-Go
go build -o spip-agent ./cmd/spip-agent
```

2) (Optional) Use the interactive setup helper
```bash
sudo ./scripts/initial_setup.sh
```
This helper writes a `config.toml` (it prompts for a short `name` used in logs), can generate self-signed TLS keys, and optionally applies the PREROUTING iptables redirect used in examples below.

3) Create or edit `config.toml`
Minimal `config.toml`:
```toml
name = "spip-agent"
ip = "127.0.0.1"
port = 8080
```

Optional configuration keys:
- `cert_path` / `key_path` — enable TLS if both set
- `log_file` — write logs to a file instead of stdout
- `read_timeout_seconds` / `write_timeout_seconds` — connection timeouts
- `rate_limit_per_second` / `rate_limit_burst` — connection rate-limiting
If these runtime tuning fields are omitted or set to `0`, Spip applies the following defaults:
- `read_timeout_seconds`: 30
- `write_timeout_seconds`: 10
- `rate_limit_per_second`: 20
- `rate_limit_burst`: 50000
4) Redirect incoming TCP to the agent (example, excluding SSH)
```bash
sudo iptables -t nat -F
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j RETURN
sudo iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port 8080
```

5) Run the agent
```bash
./spip-agent -config config.toml
```

## Log format
Spip emits each connection as a single JSON object. The output is formatted to be ECS-compatible using only the fields Spip can provide (no ASN/geo enrichment). Typical fields produced include:
- `@timestamp` — RFC3339 timestamp for the event
- `event.id` — per-connection session identifier
- `observer.hostname` / `host.name` — agent `name` from config
- `source.ip`, `source.port` and `destination.ip`, `destination.port`
- `network.transport` — e.g. `tcp`
- `http.request.body` / `url.path` — when the payload clearly resembles HTTP
- `user_agent.original` — when available
- `event.summary` — raw payload for non-HTTP probes
- `event.original_payload_hex` — raw payload hex (always preserved)

Example (ECS-shaped) record produced by Spip:
```json
{
  "@timestamp": "2025-12-01T19:35:18.123Z",
  "event": {
    "id": "bd30cdc1-95b0-49aa-b8fe-e77230b6a04f",
    "summary": "BitTorrent protocol",
    "original_payload_hex": "426974546f7272656e742070726f746f636f6c",
    "ingested_by": "spip"
  },
  "observer": {"hostname": "spip-agent"},
  "host": {"name": "spip-agent"},
  "source": {"ip": "146.70.1.1", "port": 35882},
  "destination": {"ip": "146.190.1.1", "port": 6881},
  "network": {"transport": "tcp"}
}
```

Note: the agent only emits fields it can derive from the connection payload and metadata. Downstream systems can enrich these records (geo, ASN, etc.) if desired.

## Project Structure
```
.
├── cmd/                 # Main application entry point
├── internal/            # Configuration, logging, network, TLS
├── pkg/                 # cgo helpers (socket operations)
├── test/                # End-to-end test helpers
└── scripts/             # Utility scripts (including `initial_setup.sh`)
```

## Testing
Run unit tests with:
```bash
go test ./...
```

End-to-end tests require privileges to manipulate `iptables` and are runnable via the included container helper scripts (see `scripts/`).

## Notes on HTTP parsing and deployment

Spip performs best-effort HTTP request detection from the captured payload. When the payload clearly resembles an HTTP request (valid request line plus basic headers or ALPN), the agent emits `http.*`, `url.path`, and `user_agent.original` fields. When it does not, Spip falls back to storing the payload in `event.summary` and always preserves the raw payload hex in `event.original_payload_hex`.

Because Spip reflects the source IP in its responses and accepts arbitrary inbound TCP traffic, it is intended for use as a honeypot-style sensor or edge collector in controlled/monitored environments, not on arbitrary user endpoints.
## Initial setup helper
Run the interactive helper from the repo root (requires root when applying iptables rules):
```bash
sudo ./scripts/initial_setup.sh
```
The script prompts for a short `name` written into `config.toml`, which appears in each connection log as `observer.hostname` / `host.name`.

