package capture

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"zeroflood/internal/models"
)

// PacketHandler is called every second with the latest traffic statistics.
type PacketHandler func(*models.PacketStats)

// Engine performs live packet capture on a real network interface.
type Engine struct {
	mu      sync.Mutex
	running bool
	stopCh  chan struct{}

	iface       string
	snapshotLen int32
	promiscuous bool
	timeout     time.Duration
	bpfFilter   string

	// counters (reset-on-read style via snapshot)
	totalPackets uint64
	totalBytes   uint64
	tcpCount     uint64
	udpCount     uint64
	icmpCount    uint64
	otherCount   uint64
	synCount     uint64
	ackCount     uint64
	rstCount     uint64
	finCount     uint64

	// per-second snapshot (used to compute PPS/BPS)
	prevPackets uint64
	prevBytes   uint64
	prevTime    time.Time

	// top source IPs — track per-IP packet counts
	srcIPCount map[string]uint64
	dstPorts   map[uint16]uint64

	handlers []PacketHandler
}

// New creates a real-capture Engine for the given interface.
func New(iface string, snapshotLen int32, promiscuous bool, timeout time.Duration, bpf string) *Engine {
	return &Engine{
		iface:       iface,
		snapshotLen: snapshotLen,
		promiscuous: promiscuous,
		timeout:     timeout,
		bpfFilter:   bpf,
		stopCh:      make(chan struct{}),
		srcIPCount:  make(map[string]uint64),
		dstPorts:    make(map[uint16]uint64),
		prevTime:    time.Now(),
	}
}

// AddHandler registers a callback that fires every second with fresh stats.
func (e *Engine) AddHandler(h PacketHandler) {
	e.mu.Lock()
	e.handlers = append(e.handlers, h)
	e.mu.Unlock()
}

// GetInterfaces returns all usable non-loopback interfaces.
func GetInterfaces() ([]string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		// fall back to net.Interfaces if pcap fails
		ifaces, nerr := net.Interfaces()
		if nerr != nil {
			return nil, fmt.Errorf("pcap: %w; net: %v", err, nerr)
		}
		var names []string
		for _, i := range ifaces {
			names = append(names, i.Name)
		}
		return names, nil
	}

	var names []string
	for _, d := range devs {
		names = append(names, d.Name)
	}
	return names, nil
}

// BestInterface returns the interface that carries the default route first,
// then falls back to any non-loopback, non-virtual interface with addresses.
func BestInterface() (string, error) {
	// Priority 1: ask the kernel which interface the default route uses
	// by probing a connection to 8.8.8.8 (no actual packet sent)
	if conn, err := net.DialTimeout("udp", "8.8.8.8:53", 1*time.Second); err == nil {
		localAddr := conn.LocalAddr().String()
		conn.Close()
		// localAddr looks like "172.21.158.92:port" — find which iface has this IP
		hostPart := strings.Split(localAddr, ":")[0]
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				if strings.HasPrefix(a.String(), hostPart+"/") || strings.HasPrefix(a.String(), hostPart) {
					return iface.Name, nil
				}
			}
		}
	}

	// Priority 2: pcap enumeration, skip virtual/bridge/docker interfaces
	devs, err := pcap.FindAllDevs()
	if err == nil {
		// First pass: skip all virtual/bridge interfaces
		for _, d := range devs {
			n := d.Name
			if strings.HasPrefix(n, "lo") ||
				strings.HasPrefix(n, "virbr") ||
				strings.HasPrefix(n, "docker") ||
				strings.HasPrefix(n, "br-") ||
				strings.HasPrefix(n, "vnet") ||
				strings.HasPrefix(n, "veth") ||
				n == "any" {
				continue
			}
			if len(d.Addresses) > 0 {
				return n, nil
			}
		}
		// Second pass: any non-loopback with addresses
		for _, d := range devs {
			if !strings.HasPrefix(d.Name, "lo") && len(d.Addresses) > 0 {
				return d.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no suitable interface found")
}

// Start opens the pcap handle and begins capturing in a goroutine.
func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return fmt.Errorf("capture already running on %s", e.iface)
	}

	handle, err := pcap.OpenLive(e.iface, e.snapshotLen, e.promiscuous, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open %s: %w", e.iface, err)
	}

	if e.bpfFilter != "" {
		if err := handle.SetBPFFilter(e.bpfFilter); err != nil {
			handle.Close()
			return fmt.Errorf("BPF filter error: %w", err)
		}
	}

	e.running = true
	e.stopCh = make(chan struct{})
	e.prevTime = time.Now()

	go e.captureLoop(handle)
	go e.statsLoop()

	return nil
}

// Stop signals the capture goroutine to shut down.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		close(e.stopCh)
		e.running = false
	}
}

// IsRunning returns whether capture is active.
func (e *Engine) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// captureLoop reads packets from the pcap handle and updates counters.
func (e *Engine) captureLoop(handle *pcap.Handle) {
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

	for {
		select {
		case <-e.stopCh:
			return
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return
			}
			e.processPacket(packet)
		}
	}
}

// processPacket updates all counters from a single captured packet.
func (e *Engine) processPacket(packet gopacket.Packet) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.totalPackets++
	pktLen := uint64(packet.Metadata().CaptureLength)
	e.totalBytes += pktLen

	// Network layer — source IP
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		srcIP := netLayer.NetworkFlow().Src().String()
		e.srcIPCount[srcIP]++
	}

	// Transport layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		e.tcpCount++
		e.dstPorts[uint16(tcp.DstPort)]++
		if tcp.SYN && !tcp.ACK {
			e.synCount++
		}
		if tcp.ACK {
			e.ackCount++
		}
		if tcp.RST {
			e.rstCount++
		}
		if tcp.FIN {
			e.finCount++
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		e.udpCount++
		e.dstPorts[uint16(udp.DstPort)]++
	} else if packet.Layer(layers.LayerTypeICMPv4) != nil ||
		packet.Layer(layers.LayerTypeICMPv6) != nil {
		e.icmpCount++
	} else {
		e.otherCount++
	}
}

// statsLoop fires every second, computes rates, and calls registered handlers.
func (e *Engine) statsLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			stats := e.snapshot()
			e.mu.Lock()
			handlers := make([]PacketHandler, len(e.handlers))
			copy(handlers, e.handlers)
			e.mu.Unlock()
			for _, h := range handlers {
				h(stats)
			}
		}
	}
}

// snapshot computes a point-in-time stats struct (rates since last call).
func (e *Engine) snapshot() *models.PacketStats {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(e.prevTime).Seconds()

	var pps, bps float64
	if elapsed > 0 {
		pps = float64(e.totalPackets-e.prevPackets) / elapsed
		bps = float64(e.totalBytes-e.prevBytes) / elapsed
	}
	e.prevPackets = e.totalPackets
	e.prevBytes = e.totalBytes
	e.prevTime = now

	var synAckRatio float64
	if e.ackCount > 0 {
		synAckRatio = float64(e.synCount) / float64(e.ackCount)
	} else if e.synCount > 0 {
		synAckRatio = float64(e.synCount)
	}

	// build top-5 source IPs
	topSrc := topN(e.srcIPCount, 10)

	// build top-5 destination ports
	portMap := make(map[string]uint64, len(e.dstPorts))
	for p, c := range e.dstPorts {
		portMap[fmt.Sprintf("%d", p)] = c
	}
	topPorts := topN(portMap, 10)

	return &models.PacketStats{
		Timestamp:    now,
		TotalPackets: e.totalPackets,
		TotalBytes:   e.totalBytes,
		PPS:          pps,
		BPS:          bps,
		TCP:          e.tcpCount,
		UDP:          e.udpCount,
		ICMP:         e.icmpCount,
		Other:        e.otherCount,
		SynCount:     e.synCount,
		AckCount:     e.ackCount,
		RstCount:     e.rstCount,
		FinCount:     e.finCount,
		SynAckRatio:  synAckRatio,
		TopSources:   topSrc,
		TopPorts:     topPorts,
	}
}

// GetStats returns the current stats snapshot.
func (e *Engine) GetStats() *models.PacketStats {
	return e.snapshot()
}

// topN returns the top n entries from a string→uint64 counter map.
func topN(m map[string]uint64, n int) []models.IPCounter {
	result := make([]models.IPCounter, 0, len(m))
	for k, v := range m {
		result = append(result, models.IPCounter{IP: k, Count: v})
	}
	// simple selection sort (map is small in practice)
	for i := 0; i < len(result) && i < n; i++ {
		maxIdx := i
		for j := i + 1; j < len(result); j++ {
			if result[j].Count > result[maxIdx].Count {
				maxIdx = j
			}
		}
		result[i], result[maxIdx] = result[maxIdx], result[i]
	}
	if len(result) > n {
		result = result[:n]
	}
	return result
}
