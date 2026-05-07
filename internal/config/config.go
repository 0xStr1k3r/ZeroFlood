package config

import (
	"os"
	"time"
)

type Config struct {
	Capture    CaptureConfig
	Detection  DetectionConfig
	Mitigation MitigationConfig
	API        APIConfig
	LLM        LLMConfig
}

type CaptureConfig struct {
	Interface      string
	SnapshotLength int
	Promiscuous    bool
	Timeout        time.Duration
	BPFFilter      string
}

type DetectionConfig struct {
	Thresholds ThresholdsConfig
}

type ThresholdsConfig struct {
	SynFloodSynRate      int
	SynFloodAckRatio     float64
	UdpFloodPps          int
	IcmpFloodPps         int
	HttpFloodReqPerSec   int
	ConnectionRatePerSec int
}

type MitigationConfig struct {
	AutoBlockEnabled bool
	BlockDuration    time.Duration
	RateLimitPps     int
}

type APIConfig struct {
	Port string
}

type LLMConfig struct {
	Provider    string
	APIKey      string
	Model       string
	Endpoint    string
	RateLimitMs int
	Enabled     bool
}

func Load() *Config {
	interfaceName := getEnv("CAPTURE_INTERFACE", "eth0")
	apiPort := getEnv("API_PORT", "8080")

	return &Config{
		Capture: CaptureConfig{
			Interface:      interfaceName,
			SnapshotLength: 1600,
			Promiscuous:    true,
			Timeout:        30 * time.Second,
			BPFFilter:      "",
		},
		Detection: DetectionConfig{
			Thresholds: ThresholdsConfig{
				// SYN flood: alert when > 1000 SYN/s with high SYN:ACK ratio
				SynFloodSynRate:      1000,
				SynFloodAckRatio:     0.7,
				// UDP flood: alert when total PPS > 5000 AND UDP packets dominate
				UdpFloodPps:          5000,
				// ICMP flood: alert when ICMP packets/s > 500
				IcmpFloodPps:         500,
				// HTTP flood: alert when TCP-estimated HTTP rate > 2000 req/s
				HttpFloodReqPerSec:   2000,
				// Slowloris: incomplete connections threshold
				ConnectionRatePerSec: 500,
			},
		},
		Mitigation: MitigationConfig{
			AutoBlockEnabled: true,
			BlockDuration:    5 * time.Minute,
			RateLimitPps:     100,
		},
		API: APIConfig{
			Port: apiPort,
		},
		LLM: LLMConfig{
			Provider:    getEnv("LLM_PROVIDER", ""),
			APIKey:      getEnv("LLM_API_KEY", ""),
			Model:       getEnv("LLM_MODEL", "gpt-4"),
			Endpoint:    getEnv("LLM_ENDPOINT", ""),
			RateLimitMs: 5000,
			Enabled:     getEnv("LLM_ENABLED", "false") == "true",
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
