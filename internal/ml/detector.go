package ml

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"zeroflood/internal/config"
	"zeroflood/internal/models"
)

type DetectionResult struct {
	IsAttack        bool     `json:"is_attack"`
	AttackType      string   `json:"attack_type"`
	Confidence      string   `json:"confidence"`
	Reason          string   `json:"reason"`
	Recommendations []string `json:"recommendations"`
}

type LLMDetector struct {
	cfg       *config.LLMConfig
	client    *http.Client
	mu        sync.RWMutex
	lastCheck time.Time
	rateLimit time.Duration
	enabled   bool
}

func NewLLMDetector(cfg *config.LLMConfig) *LLMDetector {
	return &LLMDetector{
		cfg:       cfg,
		client:    &http.Client{Timeout: 30 * time.Second},
		rateLimit: time.Duration(cfg.RateLimitMs) * time.Millisecond,
		enabled:   cfg.Enabled && cfg.APIKey != "",
	}
}

func (d *LLMDetector) IsEnabled() bool {
	return d.enabled
}

func (d *LLMDetector) Analyze(stats *models.PacketStats) (*DetectionResult, error) {
	if !d.enabled {
		return &DetectionResult{IsAttack: false, Reason: "LLM detection disabled"}, nil
	}

	d.mu.Lock()
	if time.Since(d.lastCheck) < d.rateLimit {
		d.mu.Unlock()
		return nil, fmt.Errorf("rate limited")
	}
	d.lastCheck = time.Now()
	d.mu.Unlock()

	prompt := d.buildPrompt(stats)

	switch d.cfg.Provider {
	case "openai":
		return d.callOpenAI(prompt)
	case "claude":
		return d.callClaude(prompt)
	case "gemini":
		return d.callGemini(prompt)
	case "nvidia":
		return d.callNVIDIA(prompt)
	default:
		return &DetectionResult{IsAttack: false, Reason: "Unknown provider"}, nil
	}
}

func (d *LLMDetector) buildPrompt(stats *models.PacketStats) string {
	return fmt.Sprintf(`Analyze this network traffic for DDoS attacks. Reply only with JSON.

Traffic: PPS=%.0f, BPS=%.0f, TCP=%d, UDP=%d, ICMP=%d, SYN=%d, ACK=%d, Ratio=%.2f

JSON: {"is_attack":true/false,"attack_type":"type","confidence":"level","reason":"text","recommendations":["action"]}`,
		stats.PPS, stats.BPS, stats.TCP, stats.UDP, stats.ICMP, stats.SynCount, stats.AckCount, stats.SynAckRatio)
}

func (d *LLMDetector) callOpenAI(prompt string) (*DetectionResult, error) {
	reqBody := map[string]interface{}{
		"model": d.cfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": "DDoS detection expert. Respond valid JSON only."},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.1,
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+d.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return d.parseResponse(resp.Body)
}

func (d *LLMDetector) callClaude(prompt string) (*DetectionResult, error) {
	reqBody := map[string]interface{}{
		"model":      d.cfg.Model,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
		"max_tokens": 300,
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(body))
	req.Header.Set("x-api-key", d.cfg.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return d.parseResponse(resp.Body)
}

func (d *LLMDetector) callGemini(prompt string) (*DetectionResult, error) {
	reqBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{"parts": []map[string]string{{"text": prompt}}},
		},
		"generationConfig": map[string]interface{}{"temperature": 0.1, "maxOutputTokens": 300},
	}

	body, _ := json.Marshal(reqBody)
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1/models/%s:generateContent?key=%s", d.cfg.Model, d.cfg.APIKey)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return d.parseResponse(resp.Body)
}

func (d *LLMDetector) callNVIDIA(prompt string) (*DetectionResult, error) {
	reqBody := map[string]interface{}{
		"messages":    []map[string]string{{"role": "user", "content": prompt}},
		"temperature": 0.1,
		"max_tokens":  300,
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", d.cfg.Endpoint, bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+d.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return d.parseResponse(resp.Body)
}

func (d *LLMDetector) parseResponse(body io.Reader) (*DetectionResult, error) {
	var resp map[string]interface{}
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		return nil, err
	}

	var content string

	if choices, ok := resp["choices"].([]interface{}); ok && len(choices) > 0 {
		if msg, ok := choices[0].(map[string]interface{})["message"].(map[string]interface{}); ok {
			content, _ = msg["content"].(string)
		}
	} else if candidates, ok := resp["candidates"].([]interface{}); ok && len(candidates) > 0 {
		if cm, ok := candidates[0].(map[string]interface{})["content"].(map[string]interface{}); ok {
			if parts, ok := cm["parts"].([]interface{}); ok && len(parts) > 0 {
				content, _ = parts[0].(map[string]interface{})["text"].(string)
			}
		}
	}

	content = extractJSON(content)

	var result DetectionResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return &DetectionResult{IsAttack: false, Reason: "Parse error", Confidence: "low"}, nil
	}

	return &result, nil
}

func extractJSON(s string) string {
	start, end := 0, len(s)
	for i := 0; i < len(s); i++ {
		if s[i] == '{' {
			start = i
			break
		}
	}
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '}' {
			end = i + 1
			break
		}
	}
	if end > start {
		return s[start:end]
	}
	return s
}

type LLMStats struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

func (d *LLMDetector) GetStats() LLMStats {
	return LLMStats{
		Enabled:  d.enabled,
		Provider: d.cfg.Provider,
		Model:    d.cfg.Model,
	}
}
