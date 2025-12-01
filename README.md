# Spip - Internet Sensor

Spip is a network monitoring tool that logs all incoming TCP traffic, including both plain and TLS-encrypted connections. It is designed for easy deployment and immediate insight into your network activity. Spip is made to run on a dedicated machine, like a honeypot, but can also be run locally.

## Quick Start

### Prerequisites
- Go 1.24.0 or later
- Linux system with iptables
- Root access (for iptables configuration)

### 1. Build the Agent
```bash
git clone https://github.com/StefanGrimminck/Spip-Go.git
cd Spip-Go
go build -o spip-agent ./cmd/spip-agent
```

### 2. Create a Configuration File
Create a file named `config.toml`. A minimal example is below; a fuller example with optional tuning is in `config.example.toml`.

Minimal `config.toml`:
```toml
ip = "127.0.0.1"
port = 8080
```

Optional fields
- `cert_path` / `key_path`: paths to TLS certificate and key. Provide both to enable TLS.
- `log_file`: path to write logs instead of stdout.
- `read_timeout_seconds` / `write_timeout_seconds`: per-connection timeouts in seconds.
- `rate_limit_per_second` / `rate_limit_burst`: rate limiter settings for incoming connections.

A commented example `config.toml` is included in the repository. Edit `config.toml` with values appropriate for your environment before running the agent.

### 3. Redirect Traffic (Example: all local TCP except SSH)
```bash
sudo iptables -t nat -F
sudo iptables -t nat -A OUTPUT -p tcp -d localhost --dport 22 -j ACCEPT
sudo iptables -t nat -A OUTPUT -p tcp -d localhost -j REDIRECT --to-port 12345
```

### 4. Run Spip
```bash
./spip-agent -config config.toml
```

You will now see all incoming TCP connections logged in structured JSON format.

## TLS Support (Optional)
To enable TLS, generate a certificate and update your configuration:
```bash
openssl genrsa -out key.pem 2048
openssl req -x509 -new -nodes -key key.pem -sha256 -days 365 -out cert.pem
```
Add to `config.toml`:
```toml
cert_path = "/path/to/cert.pem"
key_path = "/path/to/key.pem"
```

## Log Output Example
Spip logs each connection and system event as a JSON object. Example connection log:
```json
{
  "timestamp": 1688737798,
  "payload": "BitTorrent protocol",
  "payload_hex": "426974546f7272656e742070726f746f636f6c",
  "source_ip": "146.70.1.1",
  "source_port": 35882,
  "destination_ip": "146.190.1.1",
  "destination_port": 6881,
  "session_id": "bd30cdc1-95b0-49aa-b8fe-e77230b6a04f",
  "is_tls": false
}
```
System messages are also logged in JSON for easy parsing and monitoring.

## Project Structure
```
.
├── cmd/
│   └── spip-agent/        # Main application entry point
├── internal/
│   ├── config/           # Configuration handling
│   ├── logging/          # JSON logging implementation
│   ├── network/          # Network operations and socket handling
│   └── tls/             # TLS connection handling
├── pkg/
│   └── socket/          # cgo bindings for socket operations
├── test/
│   └── e2e/            # End-to-end tests
└── scripts/             # Utility scripts
```

## Testing
The project includes tests for:
- TCP and TLS connection handling
- Concurrent connection processing
- Connection reset and process restart scenarios
- Original destination preservation
- High load testing

Note: Running e2e tests requires root privileges for iptables manipulation.

## Developer

Use the provided `Makefile` for common developer tasks (for example `make fmt`, `make test`, `make e2e`). The Makefile is a local convenience only; CI runs tests directly in the workflow on clean runners.
