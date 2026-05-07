package features

import (
	"sync"
	"time"

	"zeroflood/internal/models"
)

type Extractor struct {
	mu         sync.RWMutex
	history    []models.TrafficFeature
	maxHistory int
	windowSize time.Duration

	sourceIPs   map[string]uint64
	destPorts   map[string]uint64
	windowStart time.Time

	featureChan chan models.TrafficFeature
}

func New(windowSize time.Duration, maxHistory int) *Extractor {
	return &Extractor{
		history:     make([]models.TrafficFeature, 0, maxHistory),
		maxHistory:  maxHistory,
		windowSize:  windowSize,
		sourceIPs:   make(map[string]uint64),
		destPorts:   make(map[string]uint64),
		windowStart: time.Now(),
		featureChan: make(chan models.TrafficFeature, 100),
	}
}

func (e *Extractor) Process(stats *models.PacketStats) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if time.Since(e.windowStart) >= e.windowSize {
		e.emitFeature()
		e.resetWindow()
	}
}

func (e *Extractor) emitFeature() {
	feature := models.TrafficFeature{
		Timestamp:       time.Now(),
		PacketsPerSec:   0,
		BytesPerSec:     0,
		TCPPackets:      0,
		UDPPackets:      0,
		ICMPPackets:     0,
		AvgPacketSize:   0,
		SynCount:        0,
		AckCount:        0,
		SynAckRatio:     0,
		UniqueSourceIPs: len(e.sourceIPs),
		UniqueDestPorts: len(e.destPorts),
		HTTPRequests:    0,
	}

	e.history = append(e.history, feature)
	if len(e.history) > e.maxHistory {
		e.history = e.history[1:]
	}

	select {
	case e.featureChan <- feature:
	default:
	}
}

func (e *Extractor) resetWindow() {
	e.sourceIPs = make(map[string]uint64)
	e.destPorts = make(map[string]uint64)
	e.windowStart = time.Now()
}

func (e *Extractor) GetFeatureChannel() <-chan models.TrafficFeature {
	return e.featureChan
}

func (e *Extractor) GetHistory() []models.TrafficFeature {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]models.TrafficFeature, len(e.history))
	copy(result, e.history)
	return result
}

func (e *Extractor) GetLatestFeature() *models.TrafficFeature {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.history) == 0 {
		return nil
	}

	feature := e.history[len(e.history)-1]
	return &feature
}

func (e *Extractor) ToSlice() []float64 {
	feature := e.GetLatestFeature()
	if feature == nil {
		return []float64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	}

	return []float64{
		feature.PacketsPerSec,
		feature.BytesPerSec,
		float64(feature.TCPPackets),
		float64(feature.UDPPackets),
		float64(feature.ICMPPackets),
		feature.AvgPacketSize,
		float64(feature.SynCount),
		float64(feature.AckCount),
		feature.SynAckRatio,
		float64(feature.UniqueSourceIPs),
	}
}
