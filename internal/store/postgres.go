package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"quantumshield/pkg/models"
)

// PostgresStore implements Store using PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore creates a PostgreSQL store.
func NewPostgresStore(connStr string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	return &PostgresStore{db: db}, nil
}

// Init creates the schema if it does not exist.
func (s *PostgresStore) Init(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	return s.createTables(ctx)
}

func (s *PostgresStore) createTables(ctx context.Context) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id TEXT DEFAULT '',
    status TEXT DEFAULT 'completed',
    config_json JSONB,
    summary_json JSONB,
    files_scanned INTEGER DEFAULT 0,
    lines_scanned INTEGER DEFAULT 0,
    rules_evaluated INTEGER DEFAULT 0,
    duration_ms BIGINT DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id),
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
    auto_fix BOOLEAN DEFAULT FALSE,
    fix_diff TEXT,
    confidence DOUBLE PRECISION DEFAULT 0.85,
    false_positive BOOLEAN DEFAULT FALSE,
    in_dependency BOOLEAN DEFAULT FALSE,
    dependency_chain_json JSONB,
    compliance_refs_json JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_algorithm ON findings(algorithm);
`
	_, err := s.db.ExecContext(ctx, ddl)
	return err
}

// Close closes the database connection.
func (s *PostgresStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// SaveScan persists a ScanResult and all its Findings in a single transaction.
func (s *PostgresStore) SaveScan(ctx context.Context, result *models.ScanResult) error {
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
		INSERT INTO scans (
			id, project_id, status, config_json, summary_json,
			files_scanned, lines_scanned, rules_evaluated, duration_ms,
			started_at, completed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			project_id = EXCLUDED.project_id,
			status = EXCLUDED.status,
			config_json = EXCLUDED.config_json,
			summary_json = EXCLUDED.summary_json,
			files_scanned = EXCLUDED.files_scanned,
			lines_scanned = EXCLUDED.lines_scanned,
			rules_evaluated = EXCLUDED.rules_evaluated,
			duration_ms = EXCLUDED.duration_ms,
			started_at = EXCLUDED.started_at,
			completed_at = EXCLUDED.completed_at`,
		result.ID, result.ProjectID, result.Status,
		string(configJSON), string(summaryJSON),
		result.FilesScanned, result.LinesScanned, result.RulesEvaluated,
		result.DurationMs,
		result.StartedAt.UTC(), result.CompletedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert scan: %w", err)
	}

	findingStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO findings (
			id, scan_id, rule_id, severity, category, quantum_threat,
			file_path, line_start, line_end, column_start, column_end,
			code_snippet, algorithm, key_size, usage, library, language,
			description, replacement_algo, migration_effort,
			auto_fix, fix_diff, confidence, false_positive,
			in_dependency, dependency_chain_json, compliance_refs_json, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)
		ON CONFLICT (id) DO UPDATE SET
			scan_id = EXCLUDED.scan_id,
			rule_id = EXCLUDED.rule_id,
			severity = EXCLUDED.severity,
			category = EXCLUDED.category,
			quantum_threat = EXCLUDED.quantum_threat,
			file_path = EXCLUDED.file_path,
			line_start = EXCLUDED.line_start,
			line_end = EXCLUDED.line_end,
			column_start = EXCLUDED.column_start,
			column_end = EXCLUDED.column_end,
			code_snippet = EXCLUDED.code_snippet,
			algorithm = EXCLUDED.algorithm,
			key_size = EXCLUDED.key_size,
			usage = EXCLUDED.usage,
			library = EXCLUDED.library,
			language = EXCLUDED.language,
			description = EXCLUDED.description,
			replacement_algo = EXCLUDED.replacement_algo,
			migration_effort = EXCLUDED.migration_effort,
			auto_fix = EXCLUDED.auto_fix,
			fix_diff = EXCLUDED.fix_diff,
			confidence = EXCLUDED.confidence,
			false_positive = EXCLUDED.false_positive,
			in_dependency = EXCLUDED.in_dependency,
			dependency_chain_json = EXCLUDED.dependency_chain_json,
			compliance_refs_json = EXCLUDED.compliance_refs_json,
			created_at = EXCLUDED.created_at`)
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
			f.CreatedAt.UTC(),
		)
		if err != nil {
			return fmt.Errorf("insert finding %s: %w", f.ID, err)
		}
	}

	return tx.Commit()
}

// GetScan retrieves a single ScanResult by ID, including all findings.
func (s *PostgresStore) GetScan(ctx context.Context, scanID string) (*models.ScanResult, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, project_id, status, config_json, summary_json,
		       files_scanned, lines_scanned, rules_evaluated, duration_ms,
		       started_at, completed_at
		FROM scans WHERE id = $1`, scanID)

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
func (s *PostgresStore) ListScans(ctx context.Context, limit int) ([]models.ScanResult, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, project_id, status, config_json, summary_json,
		       files_scanned, lines_scanned, rules_evaluated, duration_ms,
		       started_at, completed_at
		FROM scans
		ORDER BY completed_at DESC
		LIMIT $1`, limit)
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
func (s *PostgresStore) GetScanHistory(ctx context.Context) (*models.ScanHistory, error) {
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
func (s *PostgresStore) GetTrend(ctx context.Context, days int) ([]TrendPoint, error) {
	cutoff := time.Now().UTC().AddDate(0, 0, -days)

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, completed_at, summary_json
		FROM scans
		WHERE completed_at >= $1
		ORDER BY completed_at ASC`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("query trend: %w", err)
	}
	defer rows.Close()

	var points []TrendPoint
	for rows.Next() {
		var scanID string
		var completedAt time.Time
		var summaryJSON []byte
		if err := rows.Scan(&scanID, &completedAt, &summaryJSON); err != nil {
			return nil, fmt.Errorf("scan trend row: %w", err)
		}

		var summary models.ScanSummary
		if err := json.Unmarshal(summaryJSON, &summary); err != nil {
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
func (s *PostgresStore) scanRowToResult(row *sql.Row) (*models.ScanResult, error) {
	var (
		r                        models.ScanResult
		configJSON, summaryJSON  []byte
		startedAt, completedAt   time.Time
	)

	err := row.Scan(
		&r.ID, &r.ProjectID, &r.Status,
		&configJSON, &summaryJSON,
		&r.FilesScanned, &r.LinesScanned, &r.RulesEvaluated,
		&r.DurationMs,
		&startedAt, &completedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("scan not found")
		}
		return nil, fmt.Errorf("scan row: %w", err)
	}

	if err := json.Unmarshal(configJSON, &r.Config); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := json.Unmarshal(summaryJSON, &r.Summary); err != nil {
		return nil, fmt.Errorf("unmarshal summary: %w", err)
	}
	r.StartedAt = startedAt
	r.CompletedAt = completedAt

	return &r, nil
}

// scanRowsToResult converts a *sql.Rows cursor position into a ScanResult.
func (s *PostgresStore) scanRowsToResult(rows *sql.Rows) (*models.ScanResult, error) {
	var (
		r                        models.ScanResult
		configJSON, summaryJSON  []byte
		startedAt, completedAt   time.Time
	)

	err := rows.Scan(
		&r.ID, &r.ProjectID, &r.Status,
		&configJSON, &summaryJSON,
		&r.FilesScanned, &r.LinesScanned, &r.RulesEvaluated,
		&r.DurationMs,
		&startedAt, &completedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan rows: %w", err)
	}

	if err := json.Unmarshal(configJSON, &r.Config); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := json.Unmarshal(summaryJSON, &r.Summary); err != nil {
		return nil, fmt.Errorf("unmarshal summary: %w", err)
	}
	r.StartedAt = startedAt
	r.CompletedAt = completedAt

	return &r, nil
}

// loadFindings retrieves all findings for a given scan ID.
func (s *PostgresStore) loadFindings(ctx context.Context, scanID string) ([]models.Finding, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, scan_id, rule_id, severity, category, quantum_threat,
		       file_path, line_start, line_end, column_start, column_end,
		       code_snippet, algorithm, key_size, usage, library, language,
		       description, replacement_algo, migration_effort,
		       auto_fix, fix_diff, confidence, false_positive,
		       in_dependency, dependency_chain_json, compliance_refs_json, created_at
		FROM findings
		WHERE scan_id = $1
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
			depChainJSON, compRefsJSON         []byte
			createdAt                          time.Time
		)

		err := rows.Scan(
			&f.ID, &f.ScanID, &f.RuleID,
			&severity, &category, &quantumThreat,
			&f.FilePath, &f.LineStart, &f.LineEnd, &f.ColumnStart, &f.ColumnEnd,
			&f.CodeSnippet, &f.Algorithm, &f.KeySize, &f.Usage, &f.Library, &f.Language,
			&f.Description, &f.ReplacementAlgo, &f.MigrationEffort,
			&autoFix, &f.FixDiff, &f.Confidence, &falsePositive,
			&inDep, &depChainJSON, &compRefsJSON, &createdAt,
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
		f.CreatedAt = createdAt

		if len(depChainJSON) > 0 {
			if err := json.Unmarshal(depChainJSON, &f.DependencyChain); err != nil {
				return nil, fmt.Errorf("unmarshal dependency chain: %w", err)
			}
		}
		if len(compRefsJSON) > 0 {
			if err := json.Unmarshal(compRefsJSON, &f.ComplianceRefs); err != nil {
				return nil, fmt.Errorf("unmarshal compliance refs: %w", err)
			}
		}

		findings = append(findings, f)
	}
	return findings, rows.Err()
}
