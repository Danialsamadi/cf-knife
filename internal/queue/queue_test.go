package queue

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"cf-knife/internal/scanner"
)

func tempDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpenCreateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("db file not created: %v", err)
	}
}

func TestInitScanAndPendingTargets(t *testing.T) {
	db := tempDB(t)
	targets := []scanner.Target{
		{IP: "1.1.1.1", Port: "443", SourceRange: "1.1.1.0/24"},
		{IP: "1.1.1.2", Port: "443", SourceRange: "1.1.1.0/24"},
		{IP: "1.1.1.3", Port: "80", SourceRange: "1.1.1.0/24"},
	}
	scanID, err := db.InitScan(targets, `{"test":"config"}`)
	if err != nil {
		t.Fatalf("init scan: %v", err)
	}
	if scanID <= 0 {
		t.Fatalf("expected positive scan ID, got %d", scanID)
	}

	pending, err := db.PendingTargets(scanID)
	if err != nil {
		t.Fatalf("pending targets: %v", err)
	}
	if len(pending) != 3 {
		t.Fatalf("expected 3 pending targets, got %d", len(pending))
	}
}

func TestMarkDoneReducesPending(t *testing.T) {
	db := tempDB(t)
	targets := []scanner.Target{
		{IP: "1.1.1.1", Port: "443"},
		{IP: "1.1.1.2", Port: "443"},
	}
	scanID, _ := db.InitScan(targets, "{}")

	result := scanner.ProbeResult{
		IP:         "1.1.1.1",
		Port:       "443",
		TCPSuccess: true,
		Latency:    50 * time.Millisecond,
	}
	if err := db.MarkDone(scanID, result); err != nil {
		t.Fatalf("mark done: %v", err)
	}

	pending, _ := db.PendingTargets(scanID)
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending target, got %d", len(pending))
	}
	if pending[0].IP != "1.1.1.2" {
		t.Fatalf("unexpected pending IP: %s", pending[0].IP)
	}
}

func TestResultsRoundTrip(t *testing.T) {
	db := tempDB(t)
	targets := []scanner.Target{{IP: "10.0.0.1", Port: "443"}}
	scanID, _ := db.InitScan(targets, "{}")

	want := scanner.ProbeResult{
		IP:         "10.0.0.1",
		Port:       "443",
		TCPSuccess: true,
		TLSSuccess: true,
		Latency:    100 * time.Millisecond,
		CertIssuer: "DigiCert",
		CertMITM:   false,
	}
	_ = db.MarkDone(scanID, want)

	results, err := db.Results(scanID)
	if err != nil {
		t.Fatalf("results: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	got := results[0]
	if got.IP != want.IP || got.Port != want.Port || !got.TCPSuccess || got.CertIssuer != "DigiCert" {
		t.Fatalf("result mismatch: got %+v", got)
	}
}

func TestLatestScanID(t *testing.T) {
	db := tempDB(t)

	id, _ := db.LatestScanID()
	if id != 0 {
		t.Fatalf("expected 0 for empty DB, got %d", id)
	}

	db.InitScan([]scanner.Target{{IP: "1.1.1.1", Port: "443"}}, "{}")
	db.InitScan([]scanner.Target{{IP: "2.2.2.2", Port: "80"}}, "{}")

	id, _ = db.LatestScanID()
	if id != 2 {
		t.Fatalf("expected 2, got %d", id)
	}
}

func TestCompleteScan(t *testing.T) {
	db := tempDB(t)
	scanID, _ := db.InitScan([]scanner.Target{{IP: "1.1.1.1", Port: "443"}}, "{}")
	if err := db.CompleteScan(scanID); err != nil {
		t.Fatalf("complete scan: %v", err)
	}
}

func TestDuplicateTargetsIgnored(t *testing.T) {
	db := tempDB(t)
	targets := []scanner.Target{
		{IP: "1.1.1.1", Port: "443"},
		{IP: "1.1.1.1", Port: "443"},
	}
	scanID, err := db.InitScan(targets, "{}")
	if err != nil {
		t.Fatalf("init scan: %v", err)
	}
	pending, _ := db.PendingTargets(scanID)
	if len(pending) != 1 {
		t.Fatalf("expected 1 unique pending target, got %d", len(pending))
	}
}
