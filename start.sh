#!/bin/bash
# ZeroFlood - Start Script (real-mode only, requires root/CAP_NET_RAW for packet capture)

set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

PORT="${PORT:-8080}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}        ZeroFlood - DDoS Sensor${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Check for root / CAP_NET_RAW (required for raw packet capture)
if [ "$(id -u)" != "0" ]; then
    echo -e "${YELLOW}[!] Not running as root — using sudo for sensor (required for pcap)${NC}"
    SUDO="sudo"
else
    SUDO=""
fi

# Optional: specify interface via env var or first argument
IFACE_ARG=""
if [ -n "$1" ]; then
    IFACE_ARG="-iface $1"
    echo -e "${YELLOW}[*] Using interface: $1${NC}"
elif [ -n "$CAPTURE_INTERFACE" ]; then
    IFACE_ARG="-iface $CAPTURE_INTERFACE"
    echo -e "${YELLOW}[*] Using interface from env: $CAPTURE_INTERFACE${NC}"
else
    echo -e "${YELLOW}[*] Interface: auto-detect${NC}"
fi

# Kill any stale sensor/vite processes
pkill -f "./bin/sensor" 2>/dev/null || true
pkill -f "vite"         2>/dev/null || true
sleep 1

LOG="$PROJECT_DIR/zero.log"

# Build first if binary is missing or source is newer
if [ ! -f "./bin/sensor" ] || find ./internal ./cmd -name "*.go" -newer ./bin/sensor | grep -q .; then
    echo -e "${YELLOW}[*] Building sensor binary...${NC}"
    go build -o bin/sensor ./cmd/sensor 2>&1
    echo -e "${GREEN}[✓] Build OK${NC}"
fi

# Start sensor
echo -e "${YELLOW}[*] Starting sensor...${NC}"
nohup $SUDO ./bin/sensor -port "$PORT" $IFACE_ARG > "$LOG" 2>&1 &
SENSOR_PID=$!

# Wait for API to come up (up to 20 seconds)
echo -n "    Waiting for API"
for i in $(seq 1 20); do
    sleep 1
    if curl -sf "http://localhost:$PORT/health" > /dev/null 2>&1; then
        echo -e " ${GREEN}OK${NC}"
        break
    fi
    echo -n "."
    if [ "$i" -eq 20 ]; then
        echo -e " ${RED}FAILED${NC}"
        echo ""
        echo -e "${RED}[✗] Sensor failed to start. Last log:${NC}"
        tail -20 "$LOG"
        echo ""
        echo -e "${YELLOW}Common fixes:${NC}"
        echo "  • Install libpcap headers : sudo apt install libpcap-dev"
        echo "  • Check interface         : ip link show"
        echo "  • Run with specific iface : ./start.sh eth0"
        exit 1
    fi
done

echo -e "${GREEN}[✓] Sensor running (PID $SENSOR_PID)${NC}"

# Show capture status
STATUS=$(curl -sf "http://localhost:$PORT/api/status" 2>/dev/null || echo '{}')
IFACE_LOG=$(grep -o "Capturing on interface: [^ ]*" "$LOG" 2>/dev/null | tail -1 || echo "")
echo -e "${GREEN}[✓] $IFACE_LOG${NC}"
echo -e "${GREEN}[✓] API: http://localhost:$PORT${NC}"

# Start frontend if not already up
if ! curl -sf http://localhost:3000 > /dev/null 2>&1; then
    echo -e "${YELLOW}[*] Starting React dashboard...${NC}"
    cd web && npm run dev > "$PROJECT_DIR/front.log" 2>&1 &
    cd ..
    sleep 2
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  ZeroFlood is running!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "  Dashboard  : http://localhost:3000"
echo "  API Stats  : http://localhost:$PORT/api/stats"
echo "  Live log   : tail -f $LOG"
echo "  Stop       : Ctrl+C  (or: sudo pkill -f './bin/sensor')"
echo ""

# Keep script alive and forward Ctrl+C → clean shutdown
trap "echo ''; echo 'Stopping...'; $SUDO pkill -f './bin/sensor' 2>/dev/null; pkill -f vite 2>/dev/null; exit 0" INT TERM
wait