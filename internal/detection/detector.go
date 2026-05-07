package detection

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"zeroflood/internal/config"
	"zeroflood/internal/models"
)

type Detector struct {
	cfg *config.Config

	mu             sync.RWMutex
	alertChan      chan models.Alert
	history        []models.Alert
	lastAlertTimes map[string]time.Time
	alertCooldown  time.Duration

	synFloodTracker  *AttackTracker
	udpFloodTracker  *AttackTracker
	icmpFloodTracker *AttackTracker
	httpFloodTracker *AttackTracker
	slowlorisTracker *AttackTracker
}

type AttackTracker struct {
	mu          sync.RWMutex
	count       uint64
	rate        float64
	windowStart time.Time
	windowSize  time.Duration
}

func NewDetector(cfg *config.Config) *Detector {
	d := &Detector{
		cfg:            cfg,
		alertChan:      make(chan models.Alert, 100),
		history:        make([]models.Alert, 0, 100),
		lastAlertTimes: make(map[string]time.Time),
		alertCooldown:  30 * time.Second,

		synFloodTracker:  NewAttackTracker(10 * time.Second),
		udpFloodTracker:  NewAttackTracker(10 * time.Second),
		icmpFloodTracker: NewAttackTracker(10 * time.Second),
		httpFloodTracker: NewAttackTracker(10 * time.Second),
		slowlorisTracker: NewAttackTracker(30 * time.Second),
	}

	return d
}

func NewAttackTracker(windowSize time.Duration) *AttackTracker {
	return &AttackTracker{
		windowSize:  windowSize,
		windowStart: time.Now(),
	}
}

func (t *AttackTracker) Add(count uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if time.Since(t.windowStart) >= t.windowSize {
		t.count = 0
		t.windowStart = time.Now()
	}
	t.count += count
}

func (t *AttackTracker) GetRate() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	elapsed := time.Since(t.windowStart).Seconds()
	if elapsed > 0 {
		return float64(t.count) / elapsed
	}
	return 0
}

func (t *AttackTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.count = 0
	t.windowStart = time.Now()
}

func (d *Detector) Process(stats *models.PacketStats) {
	d.detectSYNFlood(stats)
	d.detectUDPFlood(stats)
	d.detectICMPFlood(stats)
	d.detectHTTPFlood(stats)
	d.detectSlowloris(stats)
}

// detectSYNFlood fires when there are many SYN packets with a high SYN:ACK ratio
// indicating unanswered connection attempts.
func (d *Detector) detectSYNFlood(stats *models.PacketStats) {
	thresholds := d.cfg.Detection.Thresholds

	// PPS-weighted SYN estimate: what fraction of traffic is SYN?
	var synRate float64
	if stats.TotalPackets > 0 {
		synFraction := float64(stats.SynCount) / float64(stats.TotalPackets)
		synRate = stats.PPS * synFraction
	}

	if synRate > float64(thresholds.SynFloodSynRate) &&
		stats.SynAckRatio > thresholds.SynFloodAckRatio {
		d.triggerAlert("SYN Flood", "high",
			fmt.Sprintf("SYN rate: %.0f/s (threshold: %d), SYN/ACK ratio: %.2f (threshold: %.2f)",
				synRate, thresholds.SynFloodSynRate, stats.SynAckRatio, thresholds.SynFloodAckRatio),
			stats.SynCount, stats.TopSources)
	}
}

// detectUDPFlood fires when UDP traffic dominates and PPS is very high.
func (d *Detector) detectUDPFlood(stats *models.PacketStats) {
	thresholds := d.cfg.Detection.Thresholds

	// Estimate UDP PPS from total PPS and UDP fraction
	var udpPPS float64
	if stats.TotalPackets > 0 {
		udpFraction := float64(stats.UDP) / float64(stats.TotalPackets)
		udpPPS = stats.PPS * udpFraction
	}

	if udpPPS > float64(thresholds.UdpFloodPps) {
		d.triggerAlert("UDP Flood", "critical",
			fmt.Sprintf("UDP flood: %.0f pkt/s (threshold: %d)",
				udpPPS, thresholds.UdpFloodPps),
			stats.UDP, stats.TopSources)
	}
}

// detectICMPFlood fires when ICMP traffic is abnormally high.
func (d *Detector) detectICMPFlood(stats *models.PacketStats) {
	thresholds := d.cfg.Detection.Thresholds

	var icmpPPS float64
	if stats.TotalPackets > 0 {
		icmpFraction := float64(stats.ICMP) / float64(stats.TotalPackets)
		icmpPPS = stats.PPS * icmpFraction
	}

	if icmpPPS > float64(thresholds.IcmpFloodPps) {
		d.triggerAlert("ICMP Flood", "medium",
			fmt.Sprintf("ICMP flood: %.0f pkt/s (threshold: %d)",
				icmpPPS, thresholds.IcmpFloodPps),
			stats.ICMP, stats.TopSources)
	}
}

// detectHTTPFlood estimates HTTP request rate from TCP traffic.
func (d *Detector) detectHTTPFlood(stats *models.PacketStats) {
	thresholds := d.cfg.Detection.Thresholds

	// Approximate HTTP requests from TCP PPS targeting ports 80/443
	var tcpPPS float64
	if stats.TotalPackets > 0 {
		tcpFraction := float64(stats.TCP) / float64(stats.TotalPackets)
		tcpPPS = stats.PPS * tcpFraction
	}
	// HTTP is ~half of TCP (request + response), so divide by 2
	httpRate := tcpPPS / 2.0

	if httpRate > float64(thresholds.HttpFloodReqPerSec) {
		d.triggerAlert("HTTP Flood", "high",
			fmt.Sprintf("HTTP flood: %.0f req/s estimated (threshold: %d)",
				httpRate, thresholds.HttpFloodReqPerSec),
			stats.TCP, stats.TopSources)
	}
}

// detectSlowloris fires when there are many SYNs but almost no ACKs.
func (d *Detector) detectSlowloris(stats *models.PacketStats) {
	thresholds := d.cfg.Detection.Thresholds

	incomplete := uint64(0)
	if stats.SynCount > stats.AckCount {
		incomplete = stats.SynCount - stats.AckCount
	}

	if stats.SynCount > uint64(thresholds.ConnectionRatePerSec*5) &&
		incomplete > uint64(thresholds.ConnectionRatePerSec) {
		d.triggerAlert("Slowloris", "critical",
			fmt.Sprintf("Slowloris: %d open connections without ACK (SYN:%d ACK:%d)",
				incomplete, stats.SynCount, stats.AckCount),
			incomplete, stats.TopSources)
	}
}

func (d *Detector) triggerAlert(attackType, severity, message string, count uint64, topSources ...[]models.IPCounter) {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := attackType
	if now := time.Now(); d.lastAlertTimes[key].IsZero() || now.Sub(d.lastAlertTimes[key]) > d.alertCooldown {
		// Collect top sources (variadic so callers can pass nil)
		var sources []models.IPCounter
		if len(topSources) > 0 && topSources[0] != nil {
			// Keep top 5 for the alert
			src := topSources[0]
			if len(src) > 5 {
				src = src[:5]
			}
			sources = src
		}

		alert := models.Alert{
			ID:          generateAlertID(),
			Timestamp:   time.Now(),
			Severity:    severity,
			AttackType:  attackType,
			SourceIP:    "multiple",
			DestIP:      "target",
			Message:     message,
			Count:       count,
			IsMitigated: false,
			TopSources:  sources,
		}

		d.history = append(d.history, alert)
		d.lastAlertTimes[key] = time.Now()

		if len(d.history) > 100 {
			d.history = d.history[len(d.history)-100:]
		}

		select {
		case d.alertChan <- alert:
		default:
		}
	}
}

func (d *Detector) GetAlertChannel() <-chan models.Alert {
	return d.alertChan
}

func (d *Detector) GetHistory() []models.Alert {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]models.Alert, len(d.history))
	copy(result, d.history)
	return result
}

func (d *Detector) GetStats() DetectionStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return DetectionStats{
		SYNRate:     d.synFloodTracker.GetRate(),
		UDPRate:     d.udpFloodTracker.GetRate(),
		ICMPRate:    d.icmpFloodTracker.GetRate(),
		HTTPRate:    d.httpFloodTracker.GetRate(),
		TotalAlerts: len(d.history),
	}
}

type DetectionStats struct {
	SYNRate     float64
	UDPRate     float64
	ICMPRate    float64
	HTTPRate    float64
	TotalAlerts int
}

func generateAlertID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
