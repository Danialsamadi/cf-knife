package config

import (
	"testing"
	"time"
)

func TestTiming_Levels(t *testing.T) {
	tests := []struct {
		level      int
		wantThread int
		wantRate   int
	}{
		{0, 1, 1},
		{1, 5, 10},
		{2, 50, 100},
		{3, 200, 0},
		{4, 2000, 0},
		{5, 8000, 0},
	}
	for _, tt := range tests {
		p := Timing(tt.level)
		if p.Threads != tt.wantThread {
			t.Errorf("Timing(%d).Threads = %d, want %d", tt.level, p.Threads, tt.wantThread)
		}
		if p.Rate != tt.wantRate {
			t.Errorf("Timing(%d).Rate = %d, want %d", tt.level, p.Rate, tt.wantRate)
		}
	}
}

func TestApplyTiming_NoOverride(t *testing.T) {
	c := &Config{
		Timing:  5,
		Threads: 200, // will be overridden since flag not "changed"
	}
	c.ApplyTiming(func(string) bool { return false })
	if c.Threads != 8000 {
		t.Errorf("Threads = %d, want 8000", c.Threads)
	}
	if c.Timeout != 1*time.Second {
		t.Errorf("Timeout = %v, want 1s", c.Timeout)
	}
}

func TestApplyTiming_UserOverride(t *testing.T) {
	c := &Config{
		Timing:  5,
		Threads: 42,
	}
	c.ApplyTiming(func(name string) bool {
		return name == "threads"
	})
	if c.Threads != 42 {
		t.Errorf("Threads should stay at 42 when user changed it, got %d", c.Threads)
	}
}
