package sectimeline

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/afterdarksys/osx-security-timeline/internal/collector"
	"github.com/afterdarksys/osx-security-timeline/internal/config"
	"github.com/afterdarksys/osx-security-timeline/internal/storage"
	"github.com/afterdarksys/osx-security-timeline/internal/timeline"
	"github.com/spf13/cobra"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Manage the timeline daemon",
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the timeline daemon",
	RunE:  runStart,
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the timeline daemon",
	RunE:  runStop,
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check daemon status",
	RunE:  runDaemonStatus,
}

func init() {
	rootCmd.AddCommand(daemonCmd)
	daemonCmd.AddCommand(startCmd)
	daemonCmd.AddCommand(stopCmd)
	daemonCmd.AddCommand(daemonStatusCmd)

	startCmd.Flags().BoolP("foreground", "f", false, "run in foreground")
}

func runStart(cmd *cobra.Command, args []string) error {
	foreground, _ := cmd.Flags().GetBool("foreground")

	cfg := config.DefaultConfig()
	if cfgFile != "" {
		if loadedCfg, err := config.LoadConfig(cfgFile); err == nil {
			cfg = loadedCfg
		}
	}

	if err := config.EnsureConfigDir(); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Initialize storage
	store, err := storage.NewStorage(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Initialize collector
	coll := collector.NewCollector()

	// Start HTTP server
	var httpServer *http.Server
	if cfg.EnableHTTP {
		mux := http.NewServeMux()
		setupHTTPHandlers(mux, store, coll)
		httpServer = &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.HTTPPort),
			Handler: mux,
		}
		go func() {
			if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
				log.Printf("HTTP server error: %v", err)
			}
		}()
	}

	// Start collection loop
	stopCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(cfg.CollectInterval)
		defer ticker.Stop()

		lastCollect := time.Now().Add(-24 * time.Hour) // Initial collection from last 24h

		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				events, err := coll.Collect(lastCollect)
				if err != nil {
					log.Printf("Collection error: %v", err)
					continue
				}

				if len(events) > 0 {
					if err := store.Add(events); err != nil {
						log.Printf("Storage error: %v", err)
					}
					log.Printf("Collected %d events", len(events))
				}

				lastCollect = time.Now()
			}
		}
	}()

	if foreground {
		fmt.Println("Security timeline daemon started (foreground mode)")
		fmt.Printf("HTTP API: http://localhost:%d\n", cfg.HTTPPort)
		fmt.Println("Press Ctrl+C to stop")

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		fmt.Println("\nShutting down...")
		close(stopCh)
		if httpServer != nil {
			httpServer.Close()
		}
	} else {
		fmt.Println("Security timeline daemon started")
		fmt.Printf("HTTP API: http://localhost:%d\n", cfg.HTTPPort)

		pidFile := os.ExpandEnv("$HOME/.config/sectimeline/sectimeline.pid")
		if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
			log.Printf("Warning: failed to write PID file: %v", err)
		}

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		close(stopCh)
		if httpServer != nil {
			httpServer.Close()
		}
		os.Remove(pidFile)
	}

	return nil
}

func setupHTTPHandlers(mux *http.ServeMux, store *storage.Storage, coll *collector.Collector) {
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name":    "osx-security-timeline",
			"version": "1.0.0",
			"events":  store.Count(),
		})
	})

	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Parse query parameters
		since := time.Now().Add(-24 * time.Hour)
		if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
			if parsed, err := time.Parse(time.RFC3339, sinceStr); err == nil {
				since = parsed
			}
		}

		until := time.Now()
		if untilStr := r.URL.Query().Get("until"); untilStr != "" {
			if parsed, err := time.Parse(time.RFC3339, untilStr); err == nil {
				until = parsed
			}
		}

		events := store.GetEvents(since, until)
		json.NewEncoder(w).Encode(events)
	})

	mux.HandleFunc("/timeline", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		events := store.GetAllEvents()
		tl := timeline.NewTimeline(events)
		json.NewEncoder(w).Encode(tl)
	})

	mux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		query := r.URL.Query().Get("q")
		if query == "" {
			http.Error(w, "missing query parameter 'q'", http.StatusBadRequest)
			return
		}

		events := store.GetAllEvents()
		tl := timeline.NewTimeline(events)
		result, response := tl.Query(query)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"query":    query,
			"response": response,
			"events":   result.Events,
		})
	})

	mux.HandleFunc("/summary", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		events := store.GetAllEvents()
		tl := timeline.NewTimeline(events)
		json.NewEncoder(w).Encode(tl.Summary)
	})

	mux.HandleFunc("/collect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		since := time.Now().Add(-1 * time.Hour)
		events, err := coll.Collect(since)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if len(events) > 0 {
			store.Add(events)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"collected": len(events),
		})
	})
}

func runStop(cmd *cobra.Command, args []string) error {
	pidFile := os.ExpandEnv("$HOME/.config/sectimeline/sectimeline.pid")
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("daemon not running (no PID file)")
	}

	var pid int
	fmt.Sscanf(string(data), "%d", &pid)

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("daemon not running (process not found)")
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to stop daemon: %w", err)
	}

	fmt.Printf("Sent stop signal to daemon (PID %d)\n", pid)
	return nil
}

func runDaemonStatus(cmd *cobra.Command, args []string) error {
	pidFile := os.ExpandEnv("$HOME/.config/sectimeline/sectimeline.pid")
	data, err := os.ReadFile(pidFile)
	if err != nil {
		fmt.Println("Daemon status: NOT RUNNING")
		return nil
	}

	var pid int
	fmt.Sscanf(string(data), "%d", &pid)

	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Println("Daemon status: NOT RUNNING (stale PID file)")
		return nil
	}

	if err := process.Signal(syscall.Signal(0)); err != nil {
		fmt.Println("Daemon status: NOT RUNNING (stale PID file)")
		return nil
	}

	fmt.Printf("Daemon status: RUNNING (PID %d)\n", pid)
	return nil
}
