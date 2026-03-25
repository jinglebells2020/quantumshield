package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
	"quantumshield/pkg/models"
)

// SQLiteStore implements the Store interface using SQLite.
type SQLiteStore struct {
	db   *sql.DB
	path string
}

// NewSQLiteStore creates a new SQLiteStore with the given database path.
// Use ":memory:" for an in-memory database.
func NewSQLiteStore(dbPath string) *SQLiteStore {
	return &SQLiteStore{path: dbPath}
}

// Init opens the database connection and creates the schema.
func (s *SQLiteStore) Init(ctx context.Context) error {
	db, err := sql.Open("sqlite", s.path)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	s.db = db

	// Enable WAL mode for better concurrent read performance.
	if _, err := db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		return fmt.Errorf("set WAL mode: %w", err)
	}
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		return fmt.Errorf("enable foreign keys: %w", err)
	}

	if err := s.createTables(ctx); err != nil {
		return fmt.Errorf("create tables: %w", err)
	}
	return nil
}

func (s *SQLiteStore) createTables(ctx context.Context) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project_id TEXT DEFAULT '',
    status TEXT DEFAULT 'completed',
    config_json TEXT,
    summary_json TEXT,
    files_scanned INTEGER DEFAULT 0,
    lines_scanned INTEGER DEFAULT 0,
    rules_evaluated INTEGER DEFAULT 0,
    duration_ms INTEGER DEFAULT 0,
    started_at DATETIME,
    completed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    rule_id TEXT,
    severity INTEGER,
    category INTEGER,
    quantum_threat INTEGER,
    file_path TEXT,
    line_start INTEGER,
    line_end INTEGER,
    column_start INTEGER,
    column_end INTEGER,
    code_snippet TEXT,
    algorithm TEXT,
    key_size INTEGER DEFAULT 0,
    usage TEXT,
    library TEXT,
    language TEXT,
    description TEXT,
    replacement_algo TEXT,
    migration_effort TEXT,
    auto_fix BOOLEAN DEFAULT 0,
    fix_diff TEXT,
    confidence REAL DEFAULT 0.85,
    false_positive BOOLEAN DEFAULT 0,
    in_dependency BOOLEAN DEFAULT 0,
    dependency_chain_json TEXT,
    compliance_refs_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_algorithm ON findings(algorithm);
`
	_, err := s.db.ExecContext(ctx, ddl)
	return err
}

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// SaveScan persists a ScanResult and all its Findings in a single transaction.
func (s *SQLiteStore) SaveScan(ctx context.Context, result *models.ScanResult) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	configJSON, err := json.Marshal(result.Config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	summaryJSON, err := json.Marshal(result.Summary)
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT OR REPLACE INTO scans (
			id, project_id, status, config_json, summary_json,
			files_scanned, lines_scanned, rules_evaluated, duration_ms,
			started_at, completed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.ID, result.ProjectID, result.Status,
		string(configJSON), string(summaryJSON),
		result.FilesScanned, result.LinesScanned, result.RulesEvaluated,
		result.DurationMs,
		result.StartedAt.UTC().Format(time.RFC3339),
		result.CompletedAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}

	findingStmt, err := tx.PrepareContext(ctx, `
		INSERT OR REPLACE INTO findings (
			id, scan_id, rule_id, severity, category, quantum_threat,
			file_path, line_start, line_end, column_start, column_end,
			code_snippet, algorithm, key_size, usage, library, language,
			description, replacement_algo, migration_effort,
			auto_fix, fix_diff, confidence, false_positive,
			in_dependency, dependency_chain_json, compliance_refs_json, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare finding stmt: %w", err)
	}
	defer findingStmt.Close()

	for _, f := range result.Findings {
		depChainJSON, err := json.Marshal(f.DependencyChain)
		if err != nil {
			return fmt.Errorf("marshal dependency chain: %w", err)
		}
		compRefsJSON, err := json.Marshal(f.ComplianceRefs)
		if err != nil {
			return fmt.Errorf("marshal compliance refs: %w", err)
		}

		_, err = findingStmt.ExecContext(ctx,
			f.ID, f.ScanID, f.RuleID,
			int(f.Severity), int(f.Category), int(f.QuantumThreat),
			f.FilePath, f.LineStart, f.LineEnd, f.ColumnStart, f.ColumnEnd,
			f.CodeSnippet, f.Algorithm, f.KeySize, f.Usage, f.Library, f.Language,
			f.Description, f.ReplacementAlgo, f.MigrationEffort,
			f.AutoFixAvailable, f.FixDiff, f.Confidence, f.FalsePositive,
			f.InDependency, string(depChainJSON), string(compRefsJSON),
			f.CreatedAt.UTC().Format(time.RFC3339),
		)
		if err != nil {
			return fmt.Errorf("insert finding %s: %w", f.ID, err)
		}
	}

	return tx.Commit()
}

// GetScan retrieves a single ScanResult by ID, including all findings.
func (s *SQLiteStore) GetScan(ctx context.Context, scanID string) (*models.ScanResult, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, project_id, status, config_json, summary_json,
		       files_scanned, lines_scanned, rules_evaluated, duration_ms,
		       started_at, completed_at
		FROM scans WHERE id = ?`, scanID)

	result, err := s.scanRowToResult(row)
	if err != nil {
		return nil, err
	}

	findings, err := s.loadFindings(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("load findings: %w", err)
	}
	result.Findings = findings

	return result, nil
}

// ListScans returns up to `limit` scans ordered by creation time descending.
// Findings are not loaded for performance; only the summary is populated.
func (s *SQLiteStore) ListScans(ctx context.Context, limit int) ([]models.ScanResult, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, project_id, status, config_json, summary_json,
		       files_scanned, lines_scanned, rules_evaluated, duration_ms,
		       started_at, completed_at
		FROM scans
		ORDER BY completed_at DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query scans: %w", err)
	}
	defer rows.Close()

	var results []models.ScanResult
	for rows.Next() {
		r, err := s.scanRowsToResult(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *r)
	}
	return results, rows.Err()
}

// GetScanHistory returns all scans as a ScanHistory, ordered chronologically.
func (s *SQLiteStore) GetScanHistory(ctx context.Context) (*models.ScanHistory, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, project_id, status, config_json, summary_json,
		       files_scanned, lines_scanned, rules_evaluated, duration_ms,
		       started_at, completed_at
		FROM scans
		ORDER BY started_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("query scan history: %w", err)
	}
	defer rows.Close()

	history := &models.ScanHistory{}
	for rows.Next() {
		r, err := s.scanRowsToResult(rows)
		if err != nil {
			return nil, err
		}
		if history.ProjectID == "" {
			history.ProjectID = r.ProjectID
		}
		history.Scans = append(history.Scans, *r)
	}
	return history, rows.Err()
}

// GetTrend returns trend data points from the last N days.
func (s *SQLiteStore) GetTrend(ctx context.Context, days int) ([]TrendPoint, error) {
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339)

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, completed_at, summary_json
		FROM scans
		WHERE completed_at >= ?
		ORDER BY completed_at ASC`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("query trend: %w", err)
	}
	defer rows.Close()

	var points []TrendPoint
	for rows.Next() {
		var scanID, completedAtStr, summaryJSON string
		if err := rows.Scan(&scanID, &completedAtStr, &summaryJSON); err != nil {
			return nil, fmt.Errorf("scan trend row: %w", err)
		}

		completedAt, err := time.Parse(time.RFC3339, completedAtStr)
		if err != nil {
			return nil, fmt.Errorf("parse completed_at: %w", err)
		}

		var summary models.ScanSummary
		if err := json.Unmarshal([]byte(summaryJSON), &summary); err != nil {
			return nil, fmt.Errorf("unmarshal summary: %w", err)
		}

		criticalCount := summary.BySeverity["CRITICAL"]
		highCount := summary.BySeverity["HIGH"]

		points = append(points, TrendPoint{
			ScanID:           scanID,
			Timestamp:        completedAt,
			TotalFindings:    summary.TotalFindings,
			CriticalCount:    criticalCount,
			HighCount:        highCount,
			QuantumReadiness: summary.QuantumReadiness,
			RiskScore:        summary.RiskScore,
		})
	}
	return points, rows.Err()
}

// scanRowToResult converts a single *sql.Row into a ScanResult.
func (s *SQLiteStore) scanRowToResult(row *sql.Row) (*models.ScanResult, error) {
	var (
		r                              models.ScanResult
		configJSON, summaryJSON        string
		startedAtStr, completedAtStr   string
	)

	err := row.Scan(
		&r.ID, &r.ProjectID, &r.Status,
		&configJSON, &summaryJSON,
		&r.FilesScanned, &r.LinesScanned, &r.RulesEvaluated,
		&r.DurationMs,
		&startedAtStr, &completedAtStr,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("scan not found")
		}
		return nil, fmt.Errorf("scan row: %w", err)
	}

	if err := json.Unmarshal([]byte(configJSON), &r.Config); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := json.Unmarshal([]byte(summaryJSON), &r.Summary); err != nil {
		return nil, fmt.Errorf("unmarshal summary: %w", err)
	}

	if r.StartedAt, err = time.Parse(time.RFC3339, startedAtStr); err != nil {
		return nil, fmt.Errorf("parse started_at: %w", err)
	}
	if r.CompletedAt, err = time.Parse(time.RFC3339, completedAtStr); err != nil {
		return nil, fmt.Errorf("parse completed_at: %w", err)
	}

	return &r, nil
}

// scanRowsToResult converts a *sql.Rows cursor position into a ScanResult.
func (s *SQLiteStore) scanRowsToResult(rows *sql.Rows) (*models.ScanResult, error) {
	var (
		r                              models.ScanResult
		configJSON, summaryJSON        string
		startedAtStr, completedAtStr   string
	)

	err := rows.Scan(
		&r.ID, &r.ProjectID, &r.Status,
		&configJSON, &summaryJSON,
		&r.FilesScanned, &r.LinesScanned, &r.RulesEvaluated,
		&r.DurationMs,
		&startedAtStr, &completedAtStr,
	)
	if err != nil {
		return nil, fmt.Errorf("scan rows: %w", err)
	}

	if err := json.Unmarshal([]byte(configJSON), &r.Config); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := json.Unmarshal([]byte(summaryJSON), &r.Summary); err != nil {
		return nil, fmt.Errorf("unmarshal summary: %w", err)
	}

	if r.StartedAt, err = time.Parse(time.RFC3339, startedAtStr); err != nil {
		return nil, fmt.Errorf("parse started_at: %w", err)
	}
	if r.CompletedAt, err = time.Parse(time.RFC3339, completedAtStr); err != nil {
		return nil, fmt.Errorf("parse completed_at: %w", err)
	}

	return &r, nil
}

// loadFindings retrieves all findings for a given scan ID.
func (s *SQLiteStore) loadFindings(ctx context.Context, scanID string) ([]models.Finding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, scan_id, rule_id, severity, category, quantum_threat,
		       file_path, line_start, line_end, column_start, column_end,
		       code_snippet, algorithm, key_size, usage, library, language,
		       description, replacement_algo, migration_effort,
		       auto_fix, fix_diff, confidence, false_positive,
		       in_dependency, dependency_chain_json, compliance_refs_json, created_at
		FROM findings
		WHERE scan_id = ?
		ORDER BY severity ASC, created_at ASC`, scanID)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var (
			f                                  models.Finding
			severity, category, quantumThreat  int
			autoFix, falsePositive, inDep      bool
			depChainJSON, compRefsJSON         string
			createdAtStr                       string
		)

		err := rows.Scan(
			&f.ID, &f.ScanID, &f.RuleID,
			&severity, &category, &quantumThreat,
			&f.FilePath, &f.LineStart, &f.LineEnd, &f.ColumnStart, &f.ColumnEnd,
			&f.CodeSnippet, &f.Algorithm, &f.KeySize, &f.Usage, &f.Library, &f.Language,
			&f.Description, &f.ReplacementAlgo, &f.MigrationEffort,
			&autoFix, &f.FixDiff, &f.Confidence, &falsePositive,
			&inDep, &depChainJSON, &compRefsJSON, &createdAtStr,
		)
		if err != nil {
			return nil, fmt.Errorf("scan finding row: %w", err)
		}

		f.Severity = models.Severity(severity)
		f.Category = models.AlgorithmCategory(category)
		f.QuantumThreat = models.QuantumThreatLevel(quantumThreat)
		f.AutoFixAvailable = autoFix
		f.FalsePositive = falsePositive
		f.InDependency = inDep

		if depChainJSON != "" {
			if err := json.Unmarshal([]byte(depChainJSON), &f.DependencyChain); err != nil {
				return nil, fmt.Errorf("unmarshal dependency chain: %w", err)
			}
		}
		if compRefsJSON != "" {
			if err := json.Unmarshal([]byte(compRefsJSON), &f.ComplianceRefs); err != nil {
				return nil, fmt.Errorf("unmarshal compliance refs: %w", err)
			}
		}
		if createdAtStr != "" {
			if f.CreatedAt, err = time.Parse(time.RFC3339, createdAtStr); err != nil {
				return nil, fmt.Errorf("parse finding created_at: %w", err)
			}
		}

		findings = append(findings, f)
	}
	return findings, rows.Err()
}
