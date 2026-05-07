#!/bin/bash

echo "========================================"
echo "  ZeroFlood - Diagnostic & Test"
echo "========================================"

# Kill any existing sensors
pkill -f "bin/sensor" 2>/dev/null
sleep 1

cd /home/geek/Desktop/projects/cysa-project

echo "[1] Starting sensor in REAL mode..."
./bin/sensor -port 8080 > /tmp/zeroflood-test.log 2>&1 &
PID=$!
sleep 3

echo "[2] Checking if sensor started..."
if ! curl -s http://localhost:8080/health > /dev/null 2>&1; then
    echo "ERROR: Sensor did not start!"
    cat /tmp/zeroflood-test.log
    exit 1
fi
echo "✓ Sensor started"

echo ""
echo "[3] Checking capture status..."
STATUS=$(curl -s http://localhost:8080/api/status)
CAPTURE=$(echo $STATUS | jq -r '.capture')
echo "Capture: $CAPTURE"

echo ""
echo "[4] Checking current traffic..."
STATS=$(curl -s http://localhost:8080/api/stats)
PPS=$(echo $STATUS | jq -r '.total_packets')
echo "Total packets processed: $PPS"

echo ""
echo "[5] Generate test traffic with ping..."
echo "    (Sending 100 pings to localhost)"
ping -c 100 127.0.0.1 > /dev/null 2>&1 &
sleep 2

echo ""
echo "[6] Checking for alerts..."
ALERTS=$(curl -s http://localhost:8080/api/alerts | jq 'length')
echo "Alert count: $ALERTS"

echo ""
echo "========================================"
echo "  To test with hping from another VM:"
echo "========================================"
echo ""
echo "On your VM, run:"
echo "  # SYN Flood test"
echo "  hping3 -c 1000 -d 120 -S -w 64 -p 80 --flood 192.168.1.X"
echo ""
echo "  # UDP Flood test"  
echo "  hping3 --udp -c 1000 -d 100 --flood 192.168.1.X"
echo ""
echo "  # ICMP Flood test"
echo "  hping3 -1 --flood -d 100 192.168.1.X"
echo ""
echo "Replace 192.168.1.X with your target IP"
echo ""
echo "Dashboard: http://localhost:3000"
echo "API: http://localhost:8080/api/stats"
echo ""

# Show live PPS
echo "Live PPS (run this in another terminal):"
echo "  curl -s http://localhost:8080/api/stats | jq '.stats.PPS'"