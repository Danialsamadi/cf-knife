package scanner

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFragmentConn_Write(t *testing.T) {
	tests := []struct {
		name     string
		fragSize int
		data     []byte
		wantLen  int
	}{
		{"smaller than fragment", 100, []byte("hello"), 5},
		{"exact fragment size", 5, []byte("hello"), 5},
		{"larger than fragment", 2, []byte("hello"), 5},
		{"single byte fragments", 1, []byte("abc"), 3},
		{"empty data", 10, []byte{}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()

			fc := &fragmentConn{Conn: client, fragSize: tt.fragSize}

			received := make([]byte, 0, len(tt.data))
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 1024)
				for len(received) < len(tt.data) {
					n, err := server.Read(buf)
					if err != nil {
						return
					}
					received = append(received, buf[:n]...)
				}
			}()

			n, err := fc.Write(tt.data)
			if err != nil {
				t.Fatalf("Write error: %v", err)
			}
			if n != tt.wantLen {
				t.Errorf("Write() = %d, want %d", n, tt.wantLen)
			}

			if len(tt.data) > 0 {
				<-done
				if string(received) != string(tt.data) {
					t.Errorf("received %q, want %q", received, tt.data)
				}
			}
		})
	}
}

func TestFragmentConn_WriteSplitsCorrectly(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	fc := &fragmentConn{Conn: client, fragSize: 3}
	data := []byte("abcdefgh") // 8 bytes, should produce writes of 3, 3, 2

	chunks := make(chan []byte, 10)
	go func() {
		buf := make([]byte, 10)
		for {
			n, err := server.Read(buf)
			if err != nil {
				close(chunks)
				return
			}
			c := make([]byte, n)
			copy(c, buf[:n])
			chunks <- c
		}
	}()

	n, err := fc.Write(data)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != 8 {
		t.Errorf("Write() = %d, want 8", n)
	}
}

func TestParseFragmentSizes(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{"empty returns defaults", "", DefaultFragmentSizes, false},
		{"single value", "100", []int{100}, false},
		{"multiple values", "10,50,100", []int{10, 50, 100}, false},
		{"with spaces", " 10 , 50 , 100 ", []int{10, 50, 100}, false},
		{"negative value", "-5", nil, true},
		{"zero value", "0", nil, true},
		{"non-numeric", "abc", nil, true},
		{"mixed valid and invalid", "10,abc,50", nil, true},
		{"very large value", "999999", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFragmentSizes(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d sizes, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("sizes[%d] = %d, want %d", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b , c ", []string{"a", "b", "c"}},
		{"single", []string{"single"}},
		{"", nil},
		{",,,", nil},
		{"a,,b", []string{"a", "b"}},
	}

	for _, tt := range tests {
		got := splitCSV(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("splitCSV(%q) = %v (len %d), want %v (len %d)",
				tt.input, got, len(got), tt.want, len(tt.want))
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitCSV(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestProbeDPI_LocalTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	sizes := []int{50, 100, 500}

	bestSize, err := ProbeDPI(context.Background(), addr, "127.0.0.1", 5*time.Second, sizes)
	if err != nil {
		t.Fatalf("ProbeDPI error: %v", err)
	}
	found := false
	for _, s := range sizes {
		if bestSize == s {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("bestSize=%d not in tested sizes %v", bestSize, sizes)
	}
}

func TestProbeDPI_Unreachable(t *testing.T) {
	_, err := ProbeDPI(context.Background(), "127.0.0.1:1", "example.com", 200*time.Millisecond, []int{50, 100})
	if err == nil {
		t.Error("expected error for unreachable addr")
	}
}

func TestProbeDPI_EmptySizes(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()

	bestSize, err := ProbeDPI(context.Background(), addr, "127.0.0.1", 5*time.Second, nil)
	if err != nil {
		t.Fatalf("ProbeDPI error: %v", err)
	}
	if bestSize <= 0 {
		t.Errorf("bestSize=%d, expected positive value from defaults", bestSize)
	}
}

func TestProbeDPI_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ProbeDPI(ctx, "127.0.0.1:443", "example.com", 2*time.Second, []int{50})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestProbeSNIFronting_LocalServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	srv.TLS = &tls.Config{InsecureSkipVerify: true}
	srv.StartTLS()
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	snis := []string{"test.example.com", "127.0.0.1"}

	workingSNI, err := ProbeSNIFronting(context.Background(), addr, snis, 5*time.Second)
	if err != nil {
		t.Fatalf("ProbeSNIFronting error: %v", err)
	}
	if workingSNI == "" {
		t.Error("expected a working SNI, got empty string")
	}
}

func TestProbeSNIFronting_AllFail(t *testing.T) {
	_, err := ProbeSNIFronting(context.Background(), "127.0.0.1:1", []string{"fail.test"}, 200*time.Millisecond)
	if err == nil {
		t.Error("expected error when all SNIs fail")
	}
}
