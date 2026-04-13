package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cf-knife/internal/scanner"
)

func sampleResults() []scanner.ProbeResult {
	return []scanner.ProbeResult{
		{
			IP: "1.1.1.1", Port: "443", SourceRange: "1.1.1.0/24",
			Latency: 100 * time.Millisecond, TCPSuccess: true, TLSSuccess: true,
			ScanType: "connect", ServiceName: "cloudflare",
		},
		{
			IP: "1.0.0.1", Port: "80", SourceRange: "1.0.0.0/24",
			Latency: 200 * time.Millisecond, TCPSuccess: true,
			ScanType: "connect",
		},
	}
}

func TestWriteTXT(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean_ips.txt")
	err := Write(sampleResults(), path, "txt", 5*time.Second)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if len(data) == 0 {
		t.Error("output file is empty")
	}
	// Clean list should also exist.
	listPath := filepath.Join(dir, "clean_list.txt")
	if _, err := os.Stat(listPath); os.IsNotExist(err) {
		t.Error("clean_list.txt was not created")
	}
}

func TestWriteJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.json")
	err := Write(sampleResults(), path, "json", 2*time.Second)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var results []scanner.ProbeResult
	if err := json.Unmarshal(data, &results); err != nil {
		t.Errorf("invalid JSON: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("got %d results, want 2", len(results))
	}
}

func TestWriteCSV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.csv")
	err := Write(sampleResults(), path, "csv", 1*time.Second)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if len(data) == 0 {
		t.Error("CSV output is empty")
	}
}
