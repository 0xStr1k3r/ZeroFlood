package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"zeroflood/internal/api"
	"zeroflood/internal/capture"
	"zeroflood/internal/config"
	"zeroflood/internal/detection"
	"zeroflood/internal/mitigation"
	"zeroflood/internal/ml"
	"zeroflood/internal/models"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("ZeroFlood - DDoS Detection & Mitigation Platform")
	log.Println("========================================================")

	iface := flag.String("iface", "", "Network interface to capture (auto-detected if empty)")
	port := flag.String("port", "8080", "API server port")
	flag.Parse()

	cfg := config.Load()
	cfg.API.Port = *port

	// --- Interface selection ---
	chosenIface := *iface
	if chosenIface == "" {
		// Try config env var first
		chosenIface = cfg.Capture.Interface
	}
	if chosenIface == "" || chosenIface == "eth0" {
		// Auto-detect best available interface
		best, err := capture.BestInterface()
		if err != nil {
			log.Printf("Warning: could not auto-detect interface: %v", err)
		} else {
			chosenIface = best
		}
	}

	if chosenIface == "" {
		log.Fatal("No network interface specified or detected. Use -iface <name>")
	}

	// Show all available interfaces so the user knows what's available
	ifaces, err := capture.GetInterfaces()
	if err != nil {
		log.Printf("Warning: could not list interfaces: %v", err)
	} else {
		log.Printf("Available interfaces: %v", ifaces)
	}
	log.Printf("Capturing on interface: %s", chosenIface)

	// --- Build engine ---
	engine := capture.New(
		chosenIface,
		int32(cfg.Capture.SnapshotLength),
		cfg.Capture.Promiscuous,
		cfg.Capture.Timeout,
		cfg.Capture.BPFFilter,
	)

	// --- Detection ---
	detector := detection.NewDetector(cfg)

	// --- LLM (optional) ---
	llmDetector := ml.NewLLMDetector(&cfg.LLM)
	if llmDetector.IsEnabled() {
		log.Printf("LLM Detection ENABLED: %s (%s)", cfg.LLM.Provider, cfg.LLM.Model)
	} else {
		log.Println("LLM Detection DISABLED (set LLM_ENABLED=true and provide API key)")
	}

	// --- Mitigation ---
	mitigationEngine := mitigation.New(&cfg.Mitigation)
	log.Printf("Mitigation: auto-block=%v, duration=%s",
		cfg.Mitigation.AutoBlockEnabled, cfg.Mitigation.BlockDuration)

	// --- Wire packet handler ---
	engine.AddHandler(func(stats *models.PacketStats) {
		log.Printf("[STATS] PPS:%.0f BPS:%.0fKB TCP:%d UDP:%d ICMP:%d SYN:%d ACK:%d RST:%d",
			stats.PPS, stats.BPS/1024,
			stats.TCP, stats.UDP, stats.ICMP,
			stats.SynCount, stats.AckCount, stats.RstCount)
		detector.Process(stats)
	})

	// --- Start capture ---
	if err := engine.Start(); err != nil {
		log.Fatalf("Failed to start capture: %v\n\nMake sure:\n  1. libpcap-dev is installed: sudo apt install libpcap-dev\n  2. You are running as root (or with CAP_NET_RAW): sudo ./bin/sensor\n  3. The interface '%s' exists and is up", err, chosenIface)
	}
	defer engine.Stop()

	log.Printf("Live capture started on %s", chosenIface)

	// --- Start API server ---
	server := api.New(engine, detector, llmDetector, mitigationEngine, chosenIface)

	go func() {
		addr := fmt.Sprintf(":%s", cfg.API.Port)
		log.Printf("API server listening at http://localhost%s", addr)
		if err := server.GetRouter().Run(addr); err != nil {
			log.Fatalf("API server error: %v", err)
		}
	}()

	// --- Graceful shutdown ---
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	log.Println("Running — press Ctrl+C to stop.")
	<-sigCh

	log.Println("Shutting down...")
	mitigationEngine.Cleanup()
}
