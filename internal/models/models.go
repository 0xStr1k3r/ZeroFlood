package models

import "time"

type PacketStats struct {
	Timestamp    time.Time
	TotalPackets uint64
	TotalBytes   uint64
	PPS          float64
	BPS          float64
	TCP          uint64
	UDP          uint64
	ICMP         uint64
	Other        uint64
	SynCount     uint64
	AckCount     uint64
	RstCount     uint64
	FinCount     uint64
	SynAckRatio  float64
	TopSources   []IPCounter
	TopPorts     []IPCounter
}

type TrafficFeature struct {
	Timestamp       time.Time `json:"timestamp"`
	PacketsPerSec   float64   `json:"packets_per_sec"`
	BytesPerSec     float64   `json:"bytes_per_sec"`
	TCPPackets      uint64    `json:"tcp_packets"`
	UDPPackets      uint64    `json:"udp_packets"`
	ICMPPackets     uint64    `json:"icmp_packets"`
	AvgPacketSize   float64   `json:"avg_packet_size"`
	SynCount        uint64    `json:"syn_count"`
	AckCount        uint64    `json:"ack_count"`
	SynAckRatio     float64   `json:"syn_ack_ratio"`
	UniqueSourceIPs int       `json:"unique_source_ips"`
	UniqueDestPorts int       `json:"unique_dest_ports"`
	HTTPRequests    uint64    `json:"http_requests"`
}

type Alert struct {
	ID          string      `json:"id"`
	Timestamp   time.Time   `json:"timestamp"`
	Severity    string      `json:"severity"`
	AttackType  string      `json:"attack_type"`
	SourceIP    string      `json:"source_ip"`
	DestIP      string      `json:"dest_ip"`
	Message     string      `json:"message"`
	Count       uint64      `json:"count"`
	IsMitigated bool        `json:"is_mitigated"`
	TopSources  []IPCounter `json:"top_sources,omitempty"`
}

type BlockedIP struct {
	IP          string    `json:"ip"`
	Timestamp   time.Time `json:"timestamp"`
	Duration    int       `json:"duration_seconds"`
	Reason      string    `json:"reason"`
	AttackCount int       `json:"attack_count"`
}

type TrafficData struct {
	Stats      PacketStats `json:"stats"`
	TopSources []IPCounter `json:"top_sources"`
	TopPorts   []IPCounter `json:"top_ports"`
	Alerts     []Alert     `json:"alerts"`
	BlockedIPs []BlockedIP `json:"blocked_ips"`
}

type IPCounter struct {
	IP    string `json:"ip"`
	Count uint64 `json:"count"`
}

type SystemStatus struct {
	Status       string `json:"status"`
	Capture      bool   `json:"capture"`
	Detection    bool   `json:"detection_enabled"`
	Mitigation   bool   `json:"mitigation_enabled"`
	Uptime       string `json:"uptime"`
	TotalPackets uint64 `json:"total_packets"`
	TotalAlerts  int    `json:"total_alerts"`
}
