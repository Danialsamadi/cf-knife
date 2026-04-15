package output

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
			ServerHeader: "cloudflare", CFRay: "abc-IAD",
			TLSVersion: "TLS1.3", TLSCipher: "TLS_AES_128_GCM_SHA256",
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
	content := string(data)
	if !strings.Contains(content, "1.1.1.1:443") {
		t.Error("TXT should contain 1.1.1.1:443")
	}
	if !strings.Contains(content, "tcp=ok") {
		t.Error("TXT should contain tcp=ok")
	}
	if !strings.Contains(content, "range=1.1.1.0/24") {
		t.Error("TXT should contain source range")
	}

	listPath := filepath.Join(dir, "clean_list.txt")
	listData, err := os.ReadFile(listPath)
	if err != nil {
		t.Fatalf("read clean_list: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(listData)), "\n")
	if len(lines) != 2 {
		t.Errorf("clean_list has %d lines, want 2", len(lines))
	}
	if lines[0] != "1.1.1.1:443" {
		t.Errorf("clean_list line 0 = %q, want %q", lines[0], "1.1.1.1:443")
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
	if results[0].IP != "1.1.1.1" {
		t.Errorf("first result IP = %q, want %q", results[0].IP, "1.1.1.1")
	}
	if results[0].CFRay != "abc-IAD" {
		t.Errorf("CFRay = %q, want %q", results[0].CFRay, "abc-IAD")
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

	reader := csv.NewReader(strings.NewReader(string(data)))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("parse CSV: %v", err)
	}

	// Header + 2 data rows
	if len(records) != 3 {
		t.Errorf("got %d CSV rows, want 3 (header + 2)", len(records))
	}

	header := records[0]
	if header[0] != "ip" || header[1] != "port" || header[2] != "sni" || header[3] != "latency_ms" {
		t.Errorf("unexpected header: %v", header)
	}

	row1 := records[1]
	if row1[0] != "1.1.1.1" || row1[1] != "443" {
		t.Errorf("row1 = %v, want ip=1.1.1.1 port=443", row1[:2])
	}
}

func TestWriteJSON_SortedByLatency(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.json")
	results := []scanner.ProbeResult{
		{IP: "2.2.2.2", Port: "443", Latency: 300 * time.Millisecond, TCPSuccess: true},
		{IP: "1.1.1.1", Port: "443", Latency: 100 * time.Millisecond, TCPSuccess: true},
	}
	err := Write(results, path, "json", 1*time.Second)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, _ := os.ReadFile(path)
	var loaded []scanner.ProbeResult
	json.Unmarshal(data, &loaded)

	if loaded[0].IP != "1.1.1.1" {
		t.Errorf("first result should be lowest latency, got IP=%s", loaded[0].IP)
	}
}

func TestWrite_EmptyResults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	err := Write(nil, path, "txt", 1*time.Second)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, _ := os.ReadFile(path)
	if len(data) != 0 {
		t.Errorf("expected empty file for nil results, got %d bytes", len(data))
	}
}

func TestHelpers(t *testing.T) {
	if boolOK(true) != "ok" {
		t.Error("boolOK(true) should be ok")
	}
	if boolOK(false) != "fail" {
		t.Error("boolOK(false) should be fail")
	}
	if boolStr(true) != "true" {
		t.Error("boolStr(true) should be true")
	}
	if boolStr(false) != "false" {
		t.Error("boolStr(false) should be false")
	}
	if nvl("", "fallback") != "fallback" {
		t.Error("nvl empty should return fallback")
	}
	if nvl("val", "fallback") != "val" {
		t.Error("nvl non-empty should return value")
	}
	if truncate("short", 10) != "short" {
		t.Error("truncate should not truncate short strings")
	}
	if truncate("this is a long string", 10) != "this is a…" {
		t.Errorf("truncate = %q", truncate("this is a long string", 10))
	}
}
