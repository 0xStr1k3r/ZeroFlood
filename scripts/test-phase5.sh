#!/bin/bash

echo "========================================="
echo "  ZeroFlood - Phase 5 Testing & Demo"
echo "========================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if sensor is running
check_sensor() {
    if ! curl -s http://localhost:8080/health > /dev/null 2>&1; then
        echo -e "${RED}[!] Error: ZeroFlood sensor is not running!${NC}"
        echo "    Start it with: ./bin/sensor -sim"
        exit 1
    fi
    echo -e "${GREEN}[✓] ZeroFlood sensor is running${NC}"
}

# Show stats
show_stats() {
    echo "--- Traffic Stats ---"
    curl -s http://localhost:8080/api/stats | jq -r '"PPS: " + (.stats.PPS | tostring) + " | BPS: " + (.stats.BPS | tostring) + " | TCP: " + (.stats.TCP | tostring) + " | UDP: " + (.stats.UDP | tostring)'
    echo ""
}

# Test 1: Normal Traffic
test_normal() {
    echo -e "${YELLOW}=== Test 1: Normal Traffic ===${NC}"
    echo "Waiting 3 seconds to observe normal traffic..."
    sleep 3
    show_stats
}

# Test 2: SYN Flood
test_syn_flood() {
    echo -e "${YELLOW}=== Test 2: SYN Flood Attack ===${NC}"
    echo "Injecting SYN flood attack..."
    for i in {1..10}; do
        curl -s -X POST "http://localhost:8080/api/block/10.0.0.$i?reason=SYN_Flood_Test" > /dev/null 2>&1
    done
    echo "Blocked 10 IPs. Checking alerts..."
    sleep 2
    curl -s http://localhost:8080/api/alerts | jq '.[] | select(.attack_type | contains("SYN") or contains("LLM")) | {type: .attack_type, severity: .severity, message: .message}'
    show_stats
}

# Test 3: UDP Flood
test_udp_flood() {
    echo -e "${YELLOW}=== Test 3: UDP Flood Attack ===${NC}"
    echo "Injecting UDP flood attack..."
    curl -s -X POST "http://localhost:8080/api/block/192.168.1.100?reason=UDP_Flood_Test" > /dev/null 2>&1
    sleep 2
    echo "Checking alerts..."
    curl -s http://localhost:8080/api/alerts | jq '.[] | select(.attack_type | contains("UDP")) | {type: .attack_type, severity: .severity}'
    show_stats
}

# Test 4: Mitigation Status
test_mitigation() {
    echo -e "${YELLOW}=== Test 4: Mitigation Status ===${NC}"
    echo "Mitigation status:"
    curl -s http://localhost:8080/api/mitigation | jq '.'
    echo ""
    echo "Blocked IPs:"
    curl -s http://localhost:8080/api/blocked | jq '.[] | "  - " + .ip + " (" + .reason + ")"'
}

# Test 5: Unblock IP
test_unblock() {
    echo -e "${YELLOW}=== Test 5: Unblock IP ===${NC}"
    echo "Unblocking 10.0.0.1..."
    curl -s -X DELETE "http://localhost:8080/api/block/10.0.0.1" > /dev/null
    sleep 1
    echo "Blocked IPs after unblock:"
    curl -s http://localhost:8080/api/blocked | jq 'length'
}

# Test 6: LLM Detection (if enabled)
test_llm() {
    echo -e "${YELLOW}=== Test 6: LLM Detection ===${NC}"
    LLM_STATUS=$(curl -s http://localhost:8080/api/llm | jq -r '.enabled')
    if [ "$LLM_STATUS" = "true" ]; then
        echo "LLM detection is enabled. Waiting 15s for LLM analysis..."
        sleep 15
        echo "LLM alerts:"
        curl -s http://localhost:8080/api/alerts | jq '.[] | select(.attack_type | contains("LLM")) | {type: .attack_type, severity: .severity}'
    else
        echo -e "${RED}LLM detection is disabled. Skipping...${NC}"
    fi
}

# Main test flow
main() {
    check_sensor
    echo ""
    
    test_normal
    echo ""
    
    test_syn_flood
    echo ""
    
    test_udp_flood
    echo ""
    
    test_mitigation
    echo ""
    
    test_unblock
    echo ""
    
    test_llm
    echo ""
    
    # Summary
    echo "========================================="
    echo "  Test Summary"
    echo "========================================="
    echo ""
    echo "Dashboard: http://localhost:3000"
    echo "API: http://localhost:8080/api/stats"
    echo ""
    echo "Blocked IPs:"
    curl -s http://localhost:8080/api/blocked | jq -r '.[] | "  - " + .ip + " (" + .reason + ")"'
    echo ""
    echo -e "${GREEN}All tests completed!${NC}"
}

# Run
main
