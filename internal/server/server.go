package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"quantumshield/internal/monitor"
	"quantumshield/internal/reporter"
	"quantumshield/internal/scanner"
	"quantumshield/pkg/crypto"
	"quantumshield/pkg/models"
	"quantumshield/pkg/version"
)

type Server struct {
	scanner  *scanner.Scanner
	monitor  *monitor.Monitor
	reporter *reporter.Reporter
	scans    []models.ScanResult
	mu       sync.RWMutex
}

type Config struct {
	Port        string
	WatchPath   string
	IntervalSec int
	WebhookURL  string
}

func Run(cfg Config) error {
	if cfg.Port == "" {
		cfg.Port = "8080"
	}
	if cfg.WatchPath == "" {
		cfg.WatchPath = "."
	}
	if cfg.IntervalSec == 0 {
		cfg.IntervalSec = 60
	}

	s, err := scanner.New()
	if err != nil {
		return err
	}

	mon, err := monitor.New(monitor.Config{
		TargetPath:  cfg.WatchPath,
		IntervalSec: cfg.IntervalSec,
		WebhookURL:  cfg.WebhookURL,
		Format:      "json",
	})
	if err != nil {
		return err
	}

	srv := &Server{
		scanner:  s,
		monitor:  mon,
		reporter: reporter.New("json"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", srv.handleHealth)
	mux.HandleFunc("/", srv.handleRoot)
	mux.HandleFunc("/api/v1/scan", srv.handleScan)
	mux.HandleFunc("/api/v1/scans", srv.handleListScans)
	mux.HandleFunc("/api/v1/monitor/status", srv.handleMonitorStatus)
	mux.HandleFunc("/api/v1/monitor/latest", srv.handleMonitorLatest)
	mux.HandleFunc("/api/v1/algorithms", srv.handleAlgorithms)
	mux.HandleFunc("/api/v1/migrations", srv.handleMigrations)

	handler := corsMiddleware(loggingMiddleware(mux))

	httpSrv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		log.Printf("Starting background monitor on %s (interval: %ds)", cfg.WatchPath, cfg.IntervalSec)
		if err := mon.Run(ctx); err != nil {
			log.Printf("Monitor error: %v", err)
		}
	}()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		httpSrv.Shutdown(shutdownCtx)
	}()

	log.Printf("QuantumShield Server v%s listening on :%s", version.Version, cfg.Port)
	if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":    "QuantumShield API",
		"version": version.Version,
		"status":  "operational",
		"endpoints": []string{
			"GET  /health",
			"POST /api/v1/scan",
			"GET  /api/v1/scans",
			"GET  /api/v1/monitor/status",
			"GET  /api/v1/monitor/latest",
			"GET  /api/v1/algorithms",
			"GET  /api/v1/migrations",
		},
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	stats := s.monitor.GetStats()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "healthy",
		"version":    version.Version,
		"uptime":     time.Since(stats.StartedAt).String(),
		"scan_count": stats.ScanCount,
		"findings":   stats.TotalFindings,
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req struct {
		Path      string   `json:"path"`
		Languages []string `json:"languages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Path = "."
	}
	if req.Path == "" {
		req.Path = "."
	}
	result, err := s.scanner.Scan(r.Context(), scanner.ScanOptions{
		TargetPath:  req.Path,
		Languages:   req.Languages,
		ScanConfigs: true,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	s.mu.Lock()
	s.scans = append(s.scans, *result)
	if len(s.scans) > 100 {
		s.scans = s.scans[len(s.scans)-100:]
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"count": len(s.scans),
		"scans": s.scans,
	})
}

func (s *Server) handleMonitorStatus(w http.ResponseWriter, r *http.Request) {
	stats := s.monitor.GetStats()
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleMonitorLatest(w http.ResponseWriter, r *http.Request) {
	result := s.monitor.GetLastScan()
	if result == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "no scans yet"})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAlgorithms(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, crypto.VulnerableAlgorithms)
}

func (s *Server) handleMigrations(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, crypto.MigrationMap)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
