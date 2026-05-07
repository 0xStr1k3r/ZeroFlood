#!/bin/bash

# ZeroFlood Quick Demo Script
echo "========================================"
echo "  ZeroFlood - Quick Demo"
echo "========================================"
echo ""

# Start sensor in background (simulation mode)
echo "[+] Starting ZeroFlood sensor in simulation mode..."
pkill -f "bin/sensor" 2>/dev/null
sleep 1

cd /home/geek/Desktop/projects/cysa-project
nohup ./bin/sensor -sim > /tmp/zeroflood.log 2>&1 &
SENSOR_PID=$!

sleep 3

# Check if sensor started
if ! curl -s http://localhost:8080/health > /dev/null 2>&1; then
    echo "[!] Failed to start sensor"
    exit 1
fi

echo "[✓] Sensor started (PID: $SENSOR_PID)"
echo ""

# Demo 1: Show initial stats
echo "=== Demo 1: Normal Traffic ==="
echo "Waiting 3 seconds..."
sleep 3
echo "Stats:"
curl -s http://localhost:8080/api/stats | jq -r '"PPS: " + (.stats.PPS | tostring) + " | BPS: " + (.stats.BPS | tostring)'
echo ""

# Demo 2: Inject SYN flood
echo "=== Demo 2: SYN Flood Attack ==="
echo "Injecting SYN flood..."
for i in {1..5}; do
    curl -s -X POST "http://localhost:8080/api/block/10.0.0.$i?reason=SYN_Flood_Demo" > /dev/null 2>&1
done
sleep 2
echo "Alerts generated:"
curl -s http://localhost:8080/api/alerts | jq '.[] | {type: .attack_type, severity: .severity}'
echo ""

# Demo 3: Show blocked IPs
echo "=== Demo 3: Mitigation Active ==="
echo "Blocked IPs:"
curl -s http://localhost:8080/api/blocked | jq -r '.[] | "  - \(.ip) (\(.reason))"'
echo ""

# Demo 4: Mitigation status
echo "=== Demo 4: Mitigation Status ==="
curl -s http://localhost:8080/api/mitigation | jq '.'
echo ""

# Demo 5: Unblock an IP
echo "=== Demo 5: Unblock IP ==="
echo "Unblocking 10.0.0.1..."
curl -s -X DELETE "http://localhost:8080/api/block/10.0.0.1" > /dev/null
sleep 1
echo "Remaining blocked IPs: $(curl -s http://localhost:8080/api/blocked | jq 'length')"
echo ""

# Summary
echo "========================================"
echo "  Demo Complete!"
echo "========================================"
echo ""
echo "Dashboard: http://localhost:3000"
echo "API: http://localhost:8080/api/stats"
echo ""
echo "Sensor PID: $SENSOR_PID"
echo "Log: /tmp/zeroflood.log"
echo ""
echo "To stop: kill $SENSOR_PID"
