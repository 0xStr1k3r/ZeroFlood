# ZeroFlood — DDoS Detection & Mitigation Platform

Real-time DDoS detection and automatic mitigation using live packet capture.

## Documentation

**Full documentation available at: https://zeroflood.0xchiru.dev**

## Quick Start

```bash
# Install dependencies and build
chmod +x build.sh
./build.sh

# Start (requires root for packet capture)
chmod +x start.sh
sudo ./start.sh
```

## Access

- **Dashboard**: http://localhost:3000
- **API**: http://localhost:8080/api/stats

## Prerequisites

```bash
# Install libpcap headers (required)
sudo apt install libpcap-dev
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CAPTURE_INTERFACE` | auto | Network interface |
| `API_PORT` | 8080 | API server port |
| `LLM_ENABLED` | false | Enable LLM detection |
| `LLM_PROVIDER` | — | openai, claude, gemini, nvidia |
| `LLM_API_KEY` | — | Your API key |

## Notes

- Requires **root** for packet capture and iptables
- Run on the gateway or server you want to protect
- Configure thresholds in `internal/config/config.go`