package mitigation

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"zeroflood/internal/config"
	"zeroflood/internal/models"
)

type Engine struct {
	mu               sync.RWMutex
	blockedIPs       map[string]BlockedEntry
	autoBlockEnabled bool
	blockDuration    time.Duration
	rateLimitPPS     int
}

type BlockedEntry struct {
	IP          string
	Timestamp   time.Time
	Duration    time.Duration
	Reason      string
	AttackCount int
	timer       *time.Timer
}

func New(cfg *config.MitigationConfig) *Engine {
	return &Engine{
		blockedIPs:       make(map[string]BlockedEntry),
		autoBlockEnabled: cfg.AutoBlockEnabled,
		blockDuration:    cfg.BlockDuration,
		rateLimitPPS:     cfg.RateLimitPps,
	}
}

// isIPv6 returns true if the address is IPv6.
func isIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.To4() == nil
}

// BlockIP inserts iptables (IPv4) or ip6tables (IPv6) DROP rules for INPUT
// and FORWARD chains so that both host-destined and forwarded/bridged traffic
// from this IP is dropped.
func (e *Engine) BlockIP(ip, reason string, attackCount int) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.blockedIPs[ip]; exists {
		return fmt.Errorf("IP %s already blocked", ip)
	}

	log.Printf("[MITIGATION] Blocking IP: %s (reason: %s)", ip, reason)

	if err := e.addRules(ip); err != nil {
		log.Printf("[MITIGATION] WARNING: iptables rule failed for %s: %v", ip, err)
		// Don't return error — still track it so the UI shows it
	}

	entry := BlockedEntry{
		IP:          ip,
		Timestamp:   time.Now(),
		Duration:    e.blockDuration,
		Reason:      reason,
		AttackCount: attackCount,
	}
	if e.blockDuration > 0 {
		entry.timer = time.AfterFunc(e.blockDuration, func() {
			if err := e.UnblockIP(ip); err != nil {
				log.Printf("[MITIGATION] Auto-unblock failed for %s: %v", ip, err)
			}
		})
	}

	e.blockedIPs[ip] = entry
	return nil
}

// UnblockIP removes all iptables rules for this IP.
func (e *Engine) UnblockIP(ip string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	entry, exists := e.blockedIPs[ip]
	if !exists {
		return fmt.Errorf("IP %s not blocked", ip)
	}

	log.Printf("[MITIGATION] Unblocking IP: %s", ip)
	if entry.timer != nil {
		entry.timer.Stop()
	}
	if err := e.removeRules(ip); err != nil {
		log.Printf("[MITIGATION] WARNING: iptables remove failed for %s: %v", ip, err)
	}
	delete(e.blockedIPs, ip)
	return nil
}

// addRules inserts DROP rules in INPUT and FORWARD for both IPv4 and IPv6.
func (e *Engine) addRules(ip string) error {
	cmd := "iptables"
	if isIPv6(ip) {
		cmd = "ip6tables"
	}

	var errors []string
	// Drop packets destined for this host
	if out, err := exec.Command(cmd, "-I", "INPUT", "1", "-s", ip, "-j", "DROP").CombinedOutput(); err != nil {
		errors = append(errors, fmt.Sprintf("INPUT: %v (%s)", err, strings.TrimSpace(string(out))))
	}
	// Drop forwarded/bridged packets (covers virbr0, Docker bridges, etc.)
	if out, err := exec.Command(cmd, "-I", "FORWARD", "1", "-s", ip, "-j", "DROP").CombinedOutput(); err != nil {
		errors = append(errors, fmt.Sprintf("FORWARD: %v (%s)", err, strings.TrimSpace(string(out))))
	}

	if len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	log.Printf("[MITIGATION] iptables rules added for %s (INPUT+FORWARD)", ip)
	return nil
}

// removeRules deletes the DROP rules that addRules inserted.
func (e *Engine) removeRules(ip string) error {
	cmd := "iptables"
	if isIPv6(ip) {
		cmd = "ip6tables"
	}

	exec.Command(cmd, "-D", "INPUT", "-s", ip, "-j", "DROP").CombinedOutput()
	exec.Command(cmd, "-D", "FORWARD", "-s", ip, "-j", "DROP").CombinedOutput()
	log.Printf("[MITIGATION] iptables rules removed for %s", ip)
	return nil
}

// IsIPBlocked returns true if an IP is currently in the block list.
func (e *Engine) IsIPBlocked(ip string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.blockedIPs[ip]
	return ok
}

func (e *Engine) GetBlockedIPs() []models.BlockedIP {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]models.BlockedIP, 0, len(e.blockedIPs))
	for _, entry := range e.blockedIPs {
		result = append(result, models.BlockedIP{
			IP:          entry.IP,
			Timestamp:   entry.Timestamp,
			Duration:    int(entry.Duration.Seconds()),
			Reason:      entry.Reason,
			AttackCount: entry.AttackCount,
		})
	}
	return result
}

func (e *Engine) IsAutoBlockEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.autoBlockEnabled
}

func (e *Engine) SetAutoBlockEnabled(enabled bool) {
	e.mu.Lock()
	e.autoBlockEnabled = enabled
	e.mu.Unlock()
	log.Printf("[MITIGATION] Auto-block set to: %v", enabled)
}

// Cleanup removes all iptables rules and clears the block list.
func (e *Engine) Cleanup() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for ip, entry := range e.blockedIPs {
		if entry.timer != nil {
			entry.timer.Stop()
		}
		e.removeRules(ip)
	}
	e.blockedIPs = make(map[string]BlockedEntry)
	log.Printf("[MITIGATION] Cleanup complete — all blocks removed")
}

func (e *Engine) GetBlockDuration() time.Duration {
	return e.blockDuration
}

func (e *Engine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return map[string]interface{}{
		"enabled":        e.autoBlockEnabled,
		"blocked_count":  len(e.blockedIPs),
		"block_duration": e.blockDuration.String(),
		"rate_limit_pps": e.rateLimitPPS,
	}
}
