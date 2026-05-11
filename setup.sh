#!/bin/bash
# ZeroFlood - One-time setup script
# Run once before the first use: ./setup.sh

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================"
echo -e "        ZeroFlood - Setup"
echo -e "========================================${NC}"
echo ""

# 1. Install libpcap-dev (required for real packet capture)
echo -e "${YELLOW}[1/4] Installing libpcap-dev...${NC}"
if dpkg -l libpcap-dev 2>/dev/null | grep -q "^ii"; then
    echo -e "${GREEN}[✓] libpcap-dev already installed${NC}"
else
    sudo apt-get update -qq
    sudo apt-get install -y libpcap-dev
    echo -e "${GREEN}[✓] libpcap-dev installed${NC}"
fi

# 2. Build Go binary
echo -e "${YELLOW}[2/4] Building sensor binary...${NC}"
go build -buildvcs=false -o bin/sensor ./cmd/sensor
echo -e "${GREEN}[✓] bin/sensor built${NC}"

# 3. Install Node dependencies
echo -e "${YELLOW}[3/4] Installing frontend dependencies...${NC}"
cd web
if [ ! -d node_modules ]; then
    npm install
fi
echo -e "${GREEN}[✓] Frontend dependencies ready${NC}"
cd ..

# 4. Detect network interface
echo -e "${YELLOW}[4/4] Detecting network interfaces...${NC}"
IFACES=$(ip link show | awk '/^[0-9]+:/{gsub(":",""); print $2}' | grep -v "lo")
echo -e "${GREEN}[✓] Available interfaces: $IFACES${NC}"

DEFAULT_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5; exit}')
if [ -n "$DEFAULT_IFACE" ]; then
    echo -e "${CYAN}    Recommended interface (default route): $DEFAULT_IFACE${NC}"
fi

echo ""
echo -e "${GREEN}========================================"
echo -e "  Setup complete!"
echo -e "========================================${NC}"
echo ""
echo "Start ZeroFlood:"
echo ""
if [ -n "$DEFAULT_IFACE" ]; then
    echo "  sudo ./start.sh $DEFAULT_IFACE"
else
    echo "  sudo ./start.sh <interface>"
    echo "  Example: sudo ./start.sh eth0"
fi
echo ""
echo "Or let it auto-detect the interface:"
echo "  sudo ./start.sh"
echo ""
