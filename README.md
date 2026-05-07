# ZeroFlood — DDoS Detection & Mitigation Platform

Real-time network DDoS detection and automatic mitigation using live packet capture (libpcap/gopacket).

## Features

- **Live packet capture** via libpcap — reads real traffic on any network interface
- **TCP flag analysis** — tracks SYN, ACK, RST, FIN counts per second
- **Rule-based detection** — SYN Flood, UDP Flood, ICMP Flood, HTTP Flood, Slowloris
- **LLM-powered detection** — optional AI analysis via OpenAI, Claude, Gemini, NVIDIA NIM
- **Automatic mitigation** — iptables IP blocking with auto-unblock timers
- **Web dashboard** — real-time React GUI with charts, alerts, and mitigation controls
- **REST API** — full JSON API for integration and automation

---

## Prerequisites

```bash
# Install libpcap headers (required once)
sudo apt install libpcap-dev

# Or use the setup script (installs deps, builds, detects interface)
./setup.sh
```

## Quick Start

```bash
# One-time setup
./setup.sh

# Start (auto-detects interface, requires root for raw packet capture)
sudo ./start.sh

# Or specify an interface explicitly
sudo ./start.sh eth0

# Open dashboard
xdg-open http://localhost:3000
```

## Manual Build & Run

```bash
# Install libpcap-dev first, then:
go build -o bin/sensor ./cmd/sensor

# Run (must be root or have CAP_NET_RAW)
sudo ./bin/sensor
sudo ./bin/sensor -iface eth0
sudo ./bin/sensor -iface wlan0 -port 9090
```

## Command-Line Flags

```
./bin/sensor [options]
  -iface   Network interface to capture (auto-detected if omitted)
  -port    API server port (default: 8080)
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CAPTURE_INTERFACE` | Network interface override | auto |
| `API_PORT` | API server port | 8080 |
| `LLM_ENABLED` | Enable LLM-based detection | false |
| `LLM_PROVIDER` | openai, claude, gemini, nvidia | — |
| `LLM_API_KEY` | API key for chosen provider | — |
| `LLM_MODEL` | Model name | gpt-4 |
| `LLM_ENDPOINT` | Custom API endpoint | — |

## Detection Thresholds (real traffic defaults)

| Attack | Trigger |
|--------|---------|
| SYN Flood | > 1000 SYN/s **and** SYN:ACK ratio > 0.7 |
| UDP Flood | UDP > 5000 pkt/s |
| ICMP Flood | ICMP > 500 pkt/s |
| HTTP Flood | Estimated HTTP > 2000 req/s |
| Slowloris | Many open SYN with no ACK completion |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET  /health` | — | Health check |
| `GET  /api/stats` | — | Traffic stats + alerts + blocked IPs |
| `GET  /api/status` | — | System status + uptime |
| `GET  /api/alerts` | — | Alert history |
| `GET  /api/blocked` | — | Blocked IPs |
| `GET  /api/detection` | — | Rule-based detection stats |
| `GET  /api/mitigation` | — | Mitigation configuration |
| `POST /api/block/:ip` | — | Block an IP manually |
| `DELETE /api/block/:ip` | — | Unblock an IP |

## LLM Detection (optional)

```bash
# OpenAI
export LLM_ENABLED=true LLM_PROVIDER=openai LLM_API_KEY=sk-...

# Claude
export LLM_ENABLED=true LLM_PROVIDER=claude LLM_API_KEY=sk-ant-...

# Gemini
export LLM_ENABLED=true LLM_PROVIDER=gemini LLM_API_KEY=AIza...

# NVIDIA NIM
export LLM_ENABLED=true LLM_PROVIDER=nvidia LLM_API_KEY=nv-... \
  LLM_ENDPOINT=https://integrate.api.nvidia.com/v1/chat/completions

sudo ./bin/sensor
```

## Project Structure

```
zeroflood/
├── setup.sh                  # One-time setup (install deps, build, detect iface)
├── start.sh                  # Start sensor + dashboard
├── build.sh                  # Build-only script
├── cmd/sensor/main.go        # Entry point
├── internal/
│   ├── capture/capture.go    # Real pcap packet capture (gopacket + libpcap)
│   ├── config/config.go      # Configuration + env vars
│   ├── detection/detector.go # Rule-based attack detection
│   ├── ml/detector.go        # LLM-based detection
│   ├── mitigation/engine.go  # iptables IP blocking
│   ├── api/api.go            # REST API (Gin)
│   └── models/models.go      # Shared data structures
├── web/                      # React + Vite dashboard
└── bin/sensor                # Compiled binary (after build)
```

## Notes

- Packet capture requires **root** or `CAP_NET_RAW` capability
- iptables blocking also requires root
- The sensor captures traffic on the physical interface — run on the **gateway or server** you want to protect
- All thresholds are tunable via environment variables or by editing `internal/config/config.go`