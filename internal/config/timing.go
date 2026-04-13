package config

import "time"

// TimingPreset maps nmap-style -T values to conservative defaults.
// The caller can still override individual flags.
type TimingPreset struct {
	Threads    int
	Timeout    time.Duration
	MaxLatency time.Duration
	Rate       int // 0 = unlimited
}

// Timing returns the preset for the given level (0-5).
func Timing(level int) TimingPreset {
	switch level {
	case 0: // paranoid
		return TimingPreset{Threads: 1, Timeout: 10 * time.Second, MaxLatency: 5 * time.Second, Rate: 1}
	case 1: // sneaky
		return TimingPreset{Threads: 5, Timeout: 8 * time.Second, MaxLatency: 3 * time.Second, Rate: 10}
	case 2: // polite
		return TimingPreset{Threads: 50, Timeout: 5 * time.Second, MaxLatency: 2 * time.Second, Rate: 100}
	case 3: // normal (default)
		return TimingPreset{Threads: 200, Timeout: 3 * time.Second, MaxLatency: 800 * time.Millisecond, Rate: 0}
	case 4: // aggressive
		return TimingPreset{Threads: 2000, Timeout: 2 * time.Second, MaxLatency: 500 * time.Millisecond, Rate: 0}
	case 5: // insane
		return TimingPreset{Threads: 8000, Timeout: 1 * time.Second, MaxLatency: 300 * time.Millisecond, Rate: 0}
	default:
		return Timing(3)
	}
}

// ApplyTiming sets config fields from a timing preset unless the user
// explicitly changed the corresponding flag.
func (c *Config) ApplyTiming(flagChanged func(string) bool) {
	preset := Timing(c.Timing)

	if !flagChanged("threads") {
		c.Threads = preset.Threads
	}
	if !flagChanged("timeout") {
		c.Timeout = preset.Timeout
	}
	if !flagChanged("max-latency") {
		c.MaxLatency = preset.MaxLatency
	}
	// --rate takes precedence; timing only sets it if user didn't.
	if !flagChanged("rate") {
		c.Rate = preset.Rate
	}
}
