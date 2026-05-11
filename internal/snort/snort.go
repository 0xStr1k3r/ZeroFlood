// Package snort provides integration with Snort IDS and Suricata IDS.
// It detects whichever is available and reads their alert output in real time.
// Suricata eve.json is preferred; Snort fast.log / alert_json.txt are fallbacks.
package snort

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SnortConfig holds IDS integration configuration.
type SnortConfig struct {
	Enabled   bool
	Interface string
	LogPath   string // overrides auto-detection
	RulesPath string
}

// SnortStats is returned by GetStats().
type SnortStats struct {
	Enabled     bool      `json:"enabled"`
	Status      string    `json:"status"`
	Engine      string    `json:"engine"`   // "suricata" | "snort" | "none"
	RulesLoaded int       `json:"rules_loaded"`
	Alerts      int       `json:"alerts"`
	Dropped     int       `json:"dropped"`
	LogFile     string    `json:"log_file"`
	LastUpdate  time.Time `json:"last_update"`
}

// SnortAlert is a normalised alert from any IDS engine.
type SnortAlert struct {
	Timestamp      time.Time `json:"timestamp"`
	SID            int       `json:"sid"`
	Msg            string    `json:"msg"`
	SrcIP          string    `json:"src_ip"`
	DstIP          string    `json:"dst_ip"`
	SrcPort        int       `json:"src_port"`
	DstPort        int       `json:"dst_port"`
	Protocol       string    `json:"protocol"`
	Classification string    `json:"classification"`
	Severity       int       `json:"severity"`
	RawLine        string    `json:"raw_line,omitempty"`
}

// Engine manages the IDS integration.
type Engine struct {
	mu        sync.RWMutex
	config    *SnortConfig
	stats     *SnortStats
	alerts    []SnortAlert
	AlertChan chan SnortAlert
	running   bool
	stopCh    chan struct{}
}

// New creates an Engine. It does not start reading until Start() is called.
func New(config *SnortConfig) *Engine {
	return &Engine{
		config: config,
		stats: &SnortStats{
			Enabled:     config.Enabled,
			Status:      "stopped",
			Engine:      "none",
			RulesLoaded: 0,
		},
		alerts:    make([]SnortAlert, 0),
		AlertChan: make(chan SnortAlert, 100),
	}
}

// detectLogFile discovers the active IDS log file in this priority order:
// 1. config.LogPath (if set and exists)
// 2. /var/log/suricata/eve.json
// 3. /var/log/suricata/fast.log
// 4. /var/log/snort/alert_json.txt
// 5. /var/log/snort/alert
// Returns (path, engine, error).
func detectLogFile(cfg *SnortConfig) (string, string, error) {
	if cfg.LogPath != "" {
		if _, err := os.Stat(cfg.LogPath); err == nil {
			return cfg.LogPath, "suricata", nil
		}
	}

	candidates := []struct {
		path   string
		engine string
	}{
		{"/var/log/suricata/eve.json", "suricata"},
		{"/var/log/suricata/fast.log", "suricata"},
		{"/var/log/snort/alert_json.txt", "snort"},
		{"/var/log/snort/alert", "snort"},
		{"/var/log/snort/fast.log", "snort"},
	}

	for _, c := range candidates {
		if _, err := os.Stat(c.path); err == nil {
			return c.path, c.engine, nil
		}
	}
	return "", "none", fmt.Errorf("no IDS log file found")
}

// countRules counts the number of enabled rules available.
func countRules(rulesPath string) int {
	if rulesPath == "" {
		rulesPath = "/etc/snort/rules"
	}
	count := 0
	entries, err := os.ReadDir(rulesPath)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".rules") {
			path := filepath.Join(rulesPath, e.Name())
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "alert") || strings.HasPrefix(line, "drop") {
					count++
				}
			}
			f.Close()
		}
	}
	return count
}

func isProcessRunning(name string) bool {
	err := exec.Command("pgrep", "-x", name).Run()
	return err == nil
}

// Start begins tailing the IDS log file. It is idempotent.
func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return nil
	}

	logFile, engine, err := detectLogFile(e.config)
	
	// If log file doesn't exist OR the process isn't actually running, we need to start it
	if err != nil || (!isProcessRunning("suricata") && !isProcessRunning("snort")) {
		if _, serr := exec.LookPath("suricata"); serr == nil {
			log.Printf("[SNORT] Starting Suricata daemon on interface %s...", e.config.Interface)
			// Kill any stale process first
			exec.Command("pkill", "-x", "suricata").Run()
			
			// Start suricata in daemon mode on the specific interface
			cmd := exec.Command("suricata", "-D", "-c", "/etc/suricata/suricata.yaml", "-i", e.config.Interface)
			if out, startErr := cmd.CombinedOutput(); startErr != nil {
				log.Printf("[SNORT] Failed to start Suricata: %v, output: %s", startErr, string(out))
				e.stats.Status = "start_failed"
				return fmt.Errorf("failed to start suricata: %w", startErr)
			}

			e.stats.Status = "starting_suricata"
			e.stats.Engine = "suricata"
			e.stats.Enabled = true
			e.running = true
			e.stopCh = make(chan struct{})
			go e.watchForLogFile()
			return nil
		}
		
		e.stats.Status = fmt.Sprintf("no_log_or_process: %v", err)
		e.stats.Enabled = false
		return fmt.Errorf("no IDS log and suricata not found")
	}

	e.stats.Engine = engine
	e.stats.LogFile = logFile
	e.stats.Enabled = true
	e.stats.Status = "running"
	e.running = true
	e.stopCh = make(chan struct{})

	// Count rules in background
	go func() {
		count := countRules(e.config.RulesPath)
		if count == 0 {
			// Suricata-style rule dirs
			count = countRules("/etc/suricata/rules")
		}
		e.mu.Lock()
		e.stats.RulesLoaded = count
		e.mu.Unlock()
	}()

	go e.tailLog(logFile, engine)
	return nil
}

// watchForLogFile polls until the log file appears, then starts tailLog.
func (e *Engine) watchForLogFile() {
	log.Printf("[SNORT] Waiting for IDS log file to appear...")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			logFile, engine, err := detectLogFile(e.config)
			if err == nil {
				e.mu.Lock()
				e.stats.LogFile = logFile
				e.stats.Engine = engine
				e.stats.Status = "running"
				e.mu.Unlock()
				go e.tailLog(logFile, engine)
				return
			}
		}
	}
}

// tailLog opens the log file at the current end and tails new lines.
func (e *Engine) tailLog(logFile, engine string) {
	log.Printf("[SNORT] Tailing %s log: %s", engine, logFile)

	f, err := os.Open(logFile)
	if err != nil {
		log.Printf("[SNORT] Cannot open log %s: %v", logFile, err)
		e.mu.Lock()
		e.stats.Status = fmt.Sprintf("open_error: %v", err)
		e.mu.Unlock()
		return
	}
	// Seek to end — only read new alerts, not historical ones
	f.Seek(0, io.SeekEnd)
	reader := bufio.NewReader(f)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			f.Close()
			return
		case <-ticker.C:
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break // no more data right now
				}
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				alert := e.parseLine(line, engine)
				if alert != nil {
					e.AddAlert(*alert)
					log.Printf("[SNORT] Alert: [%s] %s -> %s: %s", alert.Protocol, alert.SrcIP, alert.DstIP, alert.Msg)
				}
			}
		}
	}
}

// parseLine parses a single log line based on the engine type.
func (e *Engine) parseLine(line, engine string) *SnortAlert {
	switch engine {
	case "suricata":
		return parseEveJSON(line)
	case "snort":
		return parseSnortFastLog(line)
	}
	return nil
}

// parseEveJSON parses a Suricata eve.json line.
func parseEveJSON(line string) *SnortAlert {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil
	}

	// Only process alert events
	eventType, _ := raw["event_type"].(string)
	if eventType != "alert" {
		return nil
	}

	alert := &SnortAlert{Timestamp: time.Now()}

	if ts, ok := raw["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			alert.Timestamp = t
		}
	}
	alert.SrcIP, _ = raw["src_ip"].(string)
	alert.DstIP, _ = raw["dest_ip"].(string)

	if sp, ok := raw["src_port"].(float64); ok {
		alert.SrcPort = int(sp)
	}
	if dp, ok := raw["dest_port"].(float64); ok {
		alert.DstPort = int(dp)
	}
	alert.Protocol, _ = raw["proto"].(string)

	if alertData, ok := raw["alert"].(map[string]interface{}); ok {
		alert.Msg, _ = alertData["signature"].(string)
		if sid, ok := alertData["signature_id"].(float64); ok {
			alert.SID = int(sid)
		}
		alert.Classification, _ = alertData["category"].(string)
		if sev, ok := alertData["severity"].(float64); ok {
			alert.Severity = int(sev)
		}
	}
	return alert
}

// parseSnortFastLog parses a Snort fast-log format line.
// Format: MM/DD-HH:MM:SS.usec [**] [gid:sid:rev] msg [**] [Classification: cls] [Priority: n] {PROTO} src:sport -> dst:dport
func parseSnortFastLog(line string) *SnortAlert {
	if !strings.Contains(line, "[**]") {
		return nil
	}

	alert := &SnortAlert{
		Timestamp: time.Now(),
		RawLine:   line,
	}

	// Extract message between [**]
	parts := strings.Split(line, "[**]")
	if len(parts) >= 2 {
		msg := strings.TrimSpace(parts[1])
		// Remove [gid:sid:rev] prefix
		if idx := strings.Index(msg, "]"); idx >= 0 {
			alert.Msg = strings.TrimSpace(msg[idx+1:])
		}
	}

	// Extract SID from [gid:sid:rev]
	if idx1 := strings.Index(line, "["); idx1 >= 0 {
		if idx2 := strings.Index(line[idx1:], "]"); idx2 >= 0 {
			sidPart := line[idx1+1 : idx1+idx2]
			fields := strings.Split(sidPart, ":")
			if len(fields) >= 2 {
				alert.SID, _ = strconv.Atoi(fields[1])
			}
		}
	}

	// Extract classification
	if idx := strings.Index(line, "Classification:"); idx >= 0 {
		rest := line[idx+15:]
		if end := strings.Index(rest, "]"); end >= 0 {
			alert.Classification = strings.TrimSpace(rest[:end])
		}
	}

	// Extract priority
	if idx := strings.Index(line, "Priority:"); idx >= 0 {
		rest := strings.TrimSpace(line[idx+9:])
		if end := strings.IndexAny(rest, "] "); end >= 0 {
			rest = rest[:end]
		}
		alert.Severity, _ = strconv.Atoi(strings.TrimSpace(rest))
	}

	// Extract protocol and IPs from last part
	if idx := strings.LastIndex(line, "{"); idx >= 0 {
		rest := line[idx+1:]
		if end := strings.Index(rest, "}"); end >= 0 {
			alert.Protocol = rest[:end]
			rest = strings.TrimSpace(rest[end+1:])
			// Parse "src:sport -> dst:dport"
			if arrowIdx := strings.Index(rest, " -> "); arrowIdx >= 0 {
				srcPart := rest[:arrowIdx]
				dstPart := rest[arrowIdx+4:]
				if colonIdx := strings.LastIndex(srcPart, ":"); colonIdx >= 0 {
					alert.SrcIP = srcPart[:colonIdx]
					alert.SrcPort, _ = strconv.Atoi(srcPart[colonIdx+1:])
				}
				if colonIdx := strings.LastIndex(dstPart, ":"); colonIdx >= 0 {
					alert.DstIP = dstPart[:colonIdx]
					alert.DstPort, _ = strconv.Atoi(dstPart[colonIdx+1:])
				}
			}
		}
	}

	return alert
}

// Stop halts log tailing and kills the IDS process.
func (e *Engine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.running {
		return nil
	}
	close(e.stopCh)
	e.running = false
	e.stats.Status = "stopped"
	e.stats.Enabled = false

	// Actually stop the IDS process so it's fully disabled
	if e.stats.Engine == "suricata" || isProcessRunning("suricata") {
		log.Printf("[SNORT] Stopping Suricata process...")
		exec.Command("pkill", "-x", "suricata").Run()
	} else if e.stats.Engine == "snort" || isProcessRunning("snort") {
		log.Printf("[SNORT] Stopping Snort process...")
		exec.Command("pkill", "-x", "snort").Run()
	}

	return nil
}

func (e *Engine) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stats.Enabled
}

func (e *Engine) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

func (e *Engine) GetStats() *SnortStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	stats := *e.stats
	stats.Alerts = len(e.alerts)
	stats.LastUpdate = time.Now()
	return &stats
}

func (e *Engine) GetAlerts() []SnortAlert {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]SnortAlert, len(e.alerts))
	copy(result, e.alerts)
	return result
}

func (e *Engine) AddAlert(alert SnortAlert) {
	e.mu.Lock()
	var found bool
	for i := len(e.alerts) - 1; i >= 0; i-- {
		if e.alerts[i].SrcIP == alert.SrcIP && e.alerts[i].Msg == alert.Msg {
			e.alerts[i].Timestamp = time.Now()
			found = true
			break
		}
	}
	if !found {
		e.alerts = append(e.alerts, alert)
		if len(e.alerts) > 200 {
			e.alerts = e.alerts[len(e.alerts)-200:]
		}
		e.stats.Alerts = len(e.alerts)
	}
	e.mu.Unlock()

	select {
	case e.AlertChan <- alert:
	default:
	}
}

func (e *Engine) Toggle(enabled bool) error {
	if enabled {
		return e.Start()
	}
	return e.Stop()
}

// ParseLogLine parses a single log line — kept for API compatibility.
func (e *Engine) ParseLogLine(line string) *SnortAlert {
	e.mu.RLock()
	eng := e.stats.Engine
	e.mu.RUnlock()
	return e.parseLine(line, eng)
}
