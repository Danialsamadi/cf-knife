package scanner

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsSocketExhaustion(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"emfile substring", errors.New("dial tcp: socket: too many open files"), true},
		{"EMFILE", errors.New("EMFILE"), true},
		{"ENFILE", errors.New("ENFILE"), true},
		{"resource temporarily unavailable", errors.New("resource temporarily unavailable"), true},
		{"wsaemfile", errors.New("wsaemfile"), true},
		{"normal refused", errors.New("connection refused"), false},
		{"timeout", fmt.Errorf("i/o timeout"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSocketExhaustion(tt.err); got != tt.want {
				t.Errorf("IsSocketExhaustion(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestNewAntiCrashHTTPTransport(t *testing.T) {
	tr := NewAntiCrashHTTPTransport("127.0.0.1:443", "example.com", 5)
	if tr == nil {
		t.Fatal("nil transport")
	}
	if !tr.DisableKeepAlives {
		t.Error("expected DisableKeepAlives true")
	}
	if tr.MaxIdleConns != 0 {
		t.Error("expected MaxIdleConns 0")
	}
}
