package detection

type DetectionConfig struct {
	Enabled      bool
	SYNFlood     bool
	UDPFlood     bool
	ICMPFlood    bool
	HTTPFlood    bool
	Slowloris    bool
	AutoMitigate bool
}

func DefaultConfig() *DetectionConfig {
	return &DetectionConfig{
		Enabled:      true,
		SYNFlood:     true,
		UDPFlood:     true,
		ICMPFlood:    true,
		HTTPFlood:    true,
		Slowloris:    true,
		AutoMitigate: false,
	}
}
