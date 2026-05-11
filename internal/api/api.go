package api

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"zeroflood/internal/capture"
	"zeroflood/internal/detection"
	"zeroflood/internal/mitigation"
	"zeroflood/internal/ml"
	"zeroflood/internal/models"
	"zeroflood/internal/snort"
)

type Server struct {
	engine           *gin.Engine
	captureEngine    *capture.Engine
	detector         *detection.Detector
	llmDetector      *ml.LLMDetector
	mitigationEngine *mitigation.Engine
	snortEngine      *snort.Engine

	mu         sync.RWMutex
	alerts     []models.Alert
	blockedIPs []models.BlockedIP
	startTime  time.Time

	statsChan chan *models.PacketStats
}

func New(captureEngine *capture.Engine, detector *detection.Detector, llmDetector *ml.LLMDetector, mitigationEngine *mitigation.Engine, iface ...string) *Server {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())

	// CORS: allow frontend dev server and production access
	engine.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	ifaceName := ""
	if len(iface) > 0 {
		ifaceName = iface[0]
	}

	snortCfg := &snort.SnortConfig{
		Enabled:   false,
		Interface: ifaceName,
		RulesPath: "/etc/snort/rules",
	}
	snortEng := snort.New(snortCfg)

	server := &Server{
		engine:           engine,
		captureEngine:    captureEngine,
		detector:         detector,
		llmDetector:      llmDetector,
		mitigationEngine: mitigationEngine,
		snortEngine:      snortEng,
		startTime:        time.Now(),
		alerts:           make([]models.Alert, 0),
		blockedIPs:       make([]models.BlockedIP, 0),
		statsChan:        make(chan *models.PacketStats, 100),
	}

	server.setupRoutes()
	go server.processDetectorAlerts()
	go server.processLLMDetection()

	// Note: Snort starts disabled. The user turns it on via the GUI toggle,
	// which will invoke handleSnortToggle -> snortEng.Start() and launch processSnortAlerts.

	return server
}

func (s *Server) setupRoutes() {
	api := s.engine.Group("/api")
	{
		api.GET("/stats", s.handleStats)
		api.GET("/alerts", s.handleAlerts)
		api.GET("/blocked", s.handleBlocked)
		api.GET("/status", s.handleStatus)
		api.GET("/detection", s.handleDetection)
		api.GET("/llm", s.handleLLM)
		api.POST("/block/:ip", s.handleBlockIP)
		api.DELETE("/block/:ip", s.handleUnblockIP)
		api.GET("/mitigation", s.handleMitigation)
		api.POST("/mitigation/autoblock", s.handleToggleAutoBlock)

		// Snort endpoints
		api.GET("/snort", s.handleSnort)
		api.POST("/snort/toggle", s.handleSnortToggle)
		api.GET("/snort/alerts", s.handleSnortAlerts)
	}

	s.engine.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
}

func (s *Server) processDetectorAlerts() {
	for alert := range s.detector.GetAlertChannel() {
		s.AddAlert(alert)
		s.autoMitigate(alert)
	}
}

// processSnortAlerts reads from the Snort/Suricata engine channel
// and feeds them into the main alert list + auto-mitigation pipeline.
func (s *Server) processSnortAlerts() {
	for sa := range s.snortEngine.AlertChan {
		sev := "medium"
		switch sa.Severity {
		case 1:
			sev = "critical"
		case 2:
			sev = "high"
		case 3:
			sev = "medium"
		}
		alert := models.Alert{
			ID:         fmt.Sprintf("ids-%d", sa.SID),
			Timestamp:  sa.Timestamp,
			Severity:   sev,
			AttackType: fmt.Sprintf("IDS: %s", sa.Classification),
			SourceIP:   sa.SrcIP,
			DestIP:     sa.DstIP,
			Message:    sa.Msg,
			Count:      1,
		}
		s.AddAlert(alert)
		s.autoMitigate(alert)
	}
}

func (s *Server) processLLMDetection() {
	if s.llmDetector == nil || !s.llmDetector.IsEnabled() {
		return
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := s.captureEngine.GetStats()
		result, err := s.llmDetector.Analyze(stats)
		if err == nil && result != nil && result.IsAttack {
			alert := models.Alert{
				ID:          generateAlertID(),
				Timestamp:   time.Now(),
				Severity:    result.Confidence,
				AttackType:  "LLM: " + result.AttackType,
				SourceIP:    "LLM Analysis",
				DestIP:      "target",
				Message:     result.Reason,
				Count:       1,
				IsMitigated: false,
			}
			s.AddAlert(alert)
		}
	}
}

func (s *Server) autoMitigate(alert models.Alert) {
	if s.mitigationEngine == nil || !s.mitigationEngine.IsAutoBlockEnabled() {
		return
	}

	if alert.Severity != "high" && alert.Severity != "critical" {
		return
	}

	// Block specific IP if known
	if alert.SourceIP != "multiple" && alert.SourceIP != "LLM Analysis" && alert.SourceIP != "" {
		err := s.mitigationEngine.BlockIP(alert.SourceIP, alert.AttackType, int(alert.Count))
		if err == nil {
			s.AddBlockedIP(models.BlockedIP{
				IP:          alert.SourceIP,
				Timestamp:   time.Now(),
				Duration:    int(s.mitigationEngine.GetBlockDuration().Seconds()),
				Reason:      alert.AttackType,
				AttackCount: int(alert.Count),
			})
		}
		return
	}

	// When source is "multiple", block the top contributing IPs from the alert
	for _, src := range alert.TopSources {
		if src.IP == "" || src.Count == 0 {
			continue
		}
		err := s.mitigationEngine.BlockIP(src.IP, alert.AttackType, int(src.Count))
		if err == nil {
			s.AddBlockedIP(models.BlockedIP{
				IP:          src.IP,
				Timestamp:   time.Now(),
				Duration:    int(s.mitigationEngine.GetBlockDuration().Seconds()),
				Reason:      alert.AttackType + " (auto-blocked top source)",
				AttackCount: int(src.Count),
			})
		}
	}
}

func (s *Server) handleStats(c *gin.Context) {
	stats := s.captureEngine.GetStats()

	s.mu.RLock()
	alerts := s.alerts
	if len(alerts) > 20 {
		alerts = alerts[len(alerts)-20:]
	}
	blocked := s.blockedIPs
	s.mu.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"stats":      stats,
		"alerts":     alerts,
		"blocked":    blocked,
		"detection":  s.detector.GetStats(),
		"llm":        s.llmDetector.GetStats(),
		"mitigation": s.mitigationEngine.GetStats(),
	})
}

func (s *Server) handleAlerts(c *gin.Context) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c.JSON(http.StatusOK, gin.H{"alerts": s.alerts})
}

func (s *Server) handleBlocked(c *gin.Context) {
	blocked := s.mitigationEngine.GetBlockedIPs()
	c.JSON(http.StatusOK, gin.H{"blocked": blocked})
}

func (s *Server) handleStatus(c *gin.Context) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := s.captureEngine.GetStats()

	status := models.SystemStatus{
		Status:       "running",
		Capture:      s.captureEngine.IsRunning(),
		Detection:    true,
		Mitigation:   s.mitigationEngine.IsAutoBlockEnabled(),
		Uptime:       time.Since(s.startTime).String(),
		TotalPackets: stats.TotalPackets,
		TotalAlerts:  len(s.alerts),
	}

	c.JSON(http.StatusOK, status)
}

func (s *Server) handleDetection(c *gin.Context) {
	c.JSON(http.StatusOK, s.detector.GetStats())
}

func (s *Server) handleLLM(c *gin.Context) {
	if s.llmDetector == nil {
		c.JSON(http.StatusOK, gin.H{"enabled": false})
		return
	}
	c.JSON(http.StatusOK, s.llmDetector.GetStats())
}

func (s *Server) handleMitigation(c *gin.Context) {
	c.JSON(http.StatusOK, s.mitigationEngine.GetStats())
}

func (s *Server) handleToggleAutoBlock(c *gin.Context) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	s.mitigationEngine.SetAutoBlockEnabled(req.Enabled)
	c.JSON(http.StatusOK, gin.H{
		"auto_block": req.Enabled,
		"status":     "updated",
	})
}

func (s *Server) handleBlockIP(c *gin.Context) {
	ip := c.Param("ip")
	reason := c.DefaultQuery("reason", "Manual block")

	err := s.mitigationEngine.BlockIP(ip, reason, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.AddBlockedIP(models.BlockedIP{
		IP:          ip,
		Timestamp:   time.Now(),
		Duration:    int(s.mitigationEngine.GetBlockDuration().Seconds()),
		Reason:      reason,
		AttackCount: 0,
	})

	c.JSON(http.StatusOK, gin.H{"status": "blocked", "ip": ip})
}

func (s *Server) handleUnblockIP(c *gin.Context) {
	ip := c.Param("ip")

	err := s.mitigationEngine.UnblockIP(ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.RemoveBlockedIP(ip)
	c.JSON(http.StatusOK, gin.H{"status": "unblocked", "ip": ip})
}

func (s *Server) AddAlert(alert models.Alert) {
	// If the source IP is already blocked, ignore the alert
	if alert.SourceIP != "multiple" && alert.SourceIP != "LLM Analysis" && alert.SourceIP != "" {
		if s.mitigationEngine != nil && s.mitigationEngine.IsIPBlocked(alert.SourceIP) {
			return
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var found bool
	if alert.SourceIP != "multiple" && alert.SourceIP != "LLM Analysis" && alert.SourceIP != "" {
		for i := len(s.alerts) - 1; i >= 0; i-- {
			if s.alerts[i].SourceIP == alert.SourceIP && s.alerts[i].AttackType == alert.AttackType {
				s.alerts[i].Count += alert.Count
				s.alerts[i].Timestamp = time.Now()
				found = true
				break
			}
		}
	}

	if !found {
		s.alerts = append(s.alerts, alert)
		if len(s.alerts) > 100 {
			s.alerts = s.alerts[len(s.alerts)-100:]
		}
	}
}

func (s *Server) AddBlockedIP(ip models.BlockedIP) {
	s.mu.Lock()
	s.blockedIPs = append(s.blockedIPs, ip)
	if len(s.blockedIPs) > 50 {
		s.blockedIPs = s.blockedIPs[len(s.blockedIPs)-50:]
	}
	s.mu.Unlock()
}

func (s *Server) RemoveBlockedIP(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	newBlocked := make([]models.BlockedIP, 0)
	for _, blocked := range s.blockedIPs {
		if blocked.IP != ip {
			newBlocked = append(newBlocked, blocked)
		}
	}
	s.blockedIPs = newBlocked
}

func (s *Server) GetRouter() *gin.Engine {
	return s.engine
}

func (s *Server) GetStatsChannel() chan *models.PacketStats {
	return s.statsChan
}

func generateAlertID() string {
	b := make([]byte, 8)
	for i := range b {
		b[i] = byte(i * 17 % 256)
	}
	return fmt.Sprintf("%x", b)
}

// Snort handlers
func (s *Server) handleSnort(c *gin.Context) {
	stats := s.snortEngine.GetStats()
	c.JSON(http.StatusOK, stats)
}

func (s *Server) handleSnortToggle(c *gin.Context) {
	var request struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	err := s.snortEngine.Toggle(request.Enabled)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if request.Enabled {
		go s.processSnortAlerts()
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled": request.Enabled,
		"status":  "success",
		"engine":  s.snortEngine.GetStats().Engine,
		"log":     s.snortEngine.GetStats().LogFile,
	})
}

func (s *Server) handleSnortAlerts(c *gin.Context) {
	alerts := s.snortEngine.GetAlerts()
	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"count":  len(alerts),
	})
}
