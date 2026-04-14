package queue

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"cf-knife/internal/scanner"

	_ "modernc.org/sqlite"
)

// DB wraps a SQLite database used to persist scan targets and results.
type DB struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path and ensures the schema
// exists.
func Open(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db %q: %w", path, err)
	}
	if _, err := sqlDB.Exec("PRAGMA journal_mode=WAL"); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	if err := migrate(sqlDB); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return &DB{db: sqlDB}, nil
}

func migrate(db *sql.DB) error {
	schema := `
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    config TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME
);
CREATE TABLE IF NOT EXISTS targets (
    scan_id INTEGER REFERENCES scans(id),
    ip TEXT NOT NULL,
    port TEXT NOT NULL,
    source_range TEXT,
    status TEXT DEFAULT 'pending',
    result_json TEXT,
    PRIMARY KEY (scan_id, ip, port)
);`
	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	return nil
}

// InitScan creates a new scan entry and inserts all targets as pending.
// Returns the scan ID.
func (d *DB) InitScan(targets []scanner.Target, configJSON string) (int64, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res, err := tx.Exec("INSERT INTO scans (config) VALUES (?)", configJSON)
	if err != nil {
		return 0, fmt.Errorf("insert scan: %w", err)
	}
	scanID, _ := res.LastInsertId()

	stmt, err := tx.Prepare("INSERT OR IGNORE INTO targets (scan_id, ip, port, source_range) VALUES (?, ?, ?, ?)")
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	for _, t := range targets {
		if _, err := stmt.Exec(scanID, t.IP, t.Port, t.SourceRange); err != nil {
			return 0, fmt.Errorf("insert target %s:%s: %w", t.IP, t.Port, err)
		}
	}
	return scanID, tx.Commit()
}

// PendingTargets returns all targets in the given scan that are still pending.
func (d *DB) PendingTargets(scanID int64) ([]scanner.Target, error) {
	rows, err := d.db.Query(
		"SELECT ip, port, source_range FROM targets WHERE scan_id = ? AND status = 'pending'",
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var targets []scanner.Target
	for rows.Next() {
		var t scanner.Target
		var sr sql.NullString
		if err := rows.Scan(&t.IP, &t.Port, &sr); err != nil {
			return nil, err
		}
		t.SourceRange = sr.String
		targets = append(targets, t)
	}
	return targets, rows.Err()
}

// MarkDone marks a single target as done and stores the result JSON.
func (d *DB) MarkDone(scanID int64, result scanner.ProbeResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(
		"UPDATE targets SET status = 'done', result_json = ? WHERE scan_id = ? AND ip = ? AND port = ?",
		string(data), scanID, result.IP, result.Port,
	)
	return err
}

// Results returns all completed probe results for a scan.
func (d *DB) Results(scanID int64) ([]scanner.ProbeResult, error) {
	rows, err := d.db.Query(
		"SELECT result_json FROM targets WHERE scan_id = ? AND status = 'done' AND result_json IS NOT NULL",
		scanID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []scanner.ProbeResult
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var r scanner.ProbeResult
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			continue
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

// LatestScanID returns the most recent scan ID, or 0 if no scans exist.
func (d *DB) LatestScanID() (int64, error) {
	var id int64
	err := d.db.QueryRow("SELECT COALESCE(MAX(id), 0) FROM scans").Scan(&id)
	return id, err
}

// CompleteScan marks the scan as completed with a timestamp.
func (d *DB) CompleteScan(scanID int64) error {
	_, err := d.db.Exec(
		"UPDATE scans SET completed_at = CURRENT_TIMESTAMP WHERE id = ?",
		scanID,
	)
	return err
}

// Close closes the underlying database connection.
func (d *DB) Close() error {
	return d.db.Close()
}
