#!/bin/bash

echo "=========================================="
echo "  ZeroFlood Demo - Attack Simulation"
echo "=========================================="
echo ""

# Check if sensor is running
if ! curl -s http://localhost:8080/health > /dev/null 2>&1; then
    echo "[!] Error: ZeroFlood sensor is not running!"
    echo "    Start it with: ./bin/sensor -sim"
    exit 1
fi

echo "[+] ZeroFlood sensor is running"
echo ""

# Function to show current stats
show_stats() {
    echo "--- Current Traffic Stats ---"
    curl -s http://localhost:8080/api/stats | jq -r '
        "PPS: " + (.stats.PPS | tostring) + 
        " | BPS: " + (.stats.BPS | tostring) + 
        " | TCP: " + (.stats.TCP | tostring) + 
        " | UDP: " + (.stats.UDP | tostring)
    '
    echo ""
}

# Test 1: Normal Traffic
echo "=== Test 1: Normal Traffic (No Attack) ==="
echo "Waiting 5 seconds to observe normal traffic..."
sleep 5
show_stats

# Test 2: SYN Flood Simulation
echo ""
echo "=== Test 2: SYN Flood Attack ==="
echo "Injecting SYN flood attack..."
for i in {1..10}; do
    curl -s -X POST "http://localhost:8080/api/block/10.0.0.$i?reason=SYN_Flood_Test" > /dev/null 2>&1
done
echo "Blocked 10 IPs. Checking alerts..."
sleep 2
curl -s http://localhost:8080/api/alerts | jq '.[] | select(.attack_type | contains("SYN") or contains("LLM")) | {type: .attack_type, severity: .severity, message: .message}'
show_stats

# Test 3: UDP Flood
echo ""
echo "=== Test 3: UDP Flood Attack ==="
echo "Injecting UDP flood..."
curl -s -X POST "http://localhost:8080/api/block/192.168.1.100?reason=UDP_Flood_Test" > /dev/null 2>&1
sleep 2
curl -s http://localhost:8080/api/alerts | jq '.[] | select(.attack_type | contains("UDP")) | {type: .attack_type, severity: .severity}'
show_stats

# Test 4: Check Mitigation Status
echo ""
echo "=== Mitigation Status ==="
curl -s http://localhost:8080/api/mitigation | jq '.'
echo ""
echo "=== Blocked IPs ==="
curl -s http://localhost:8080/api/blocked | jq '.'
echo ""

# Test 5: Unblock an IP
echo ""
echo "=== Test 5: Unblock IP ==="
echo "Unblocking 10.0.0.1..."
curl -s -X DELETE http://localhost:8080/api/block/10.0.0.1 > /dev/null
sleep 1
echo "Blocked IPs after unblock:"
curl -s http://localhost:8080/api/blocked | jq 'length'
echo ""

# Summary
echo "=========================================="
echo "  Demo Complete!"
echo "=========================================="
echo ""
echo "Dashboard: http://localhost:3000"
echo "API: http://localhost:8080/api/stats"
echo ""
echo "Blocked IPs:"
curl -s http://localhost:8080/api/blocked | jq -r '.[] | "  - \(.ip) (\(.reason)"'
