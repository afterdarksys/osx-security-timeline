package sectimeline

import (
	"fmt"
	"time"

	"github.com/afterdarksys/osx-security-timeline/internal/collector"
	"github.com/afterdarksys/osx-security-timeline/internal/config"
	"github.com/afterdarksys/osx-security-timeline/internal/storage"
	"github.com/spf13/cobra"
)

var collectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Collect security events now",
	Long:  `Manually trigger event collection without running the daemon.`,
	RunE:  runCollect,
}

var exportCmd = &cobra.Command{
	Use:   "export [file]",
	Short: "Export timeline to file",
	Long:  `Export all timeline events to a JSON file.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runExport,
}

var importCmd = &cobra.Command{
	Use:   "import [file]",
	Short: "Import timeline from file",
	Long:  `Import timeline events from a JSON file.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runImport,
}

var pruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Prune old events",
	Long:  `Remove events older than the retention period.`,
	RunE:  runPrune,
}

func init() {
	rootCmd.AddCommand(collectCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(importCmd)
	rootCmd.AddCommand(pruneCmd)

	collectCmd.Flags().StringP("since", "s", "24h", "collect events since (e.g., 1h, 24h, 7d)")
	pruneCmd.Flags().IntP("days", "d", 90, "keep events from last N days")
}

func runCollect(cmd *cobra.Command, args []string) error {
	sinceStr, _ := cmd.Flags().GetString("since")

	cfg := config.DefaultConfig()

	// Parse since duration
	var since time.Time
	switch {
	case len(sinceStr) > 1:
		unit := sinceStr[len(sinceStr)-1]
		value := sinceStr[:len(sinceStr)-1]
		var n int
		fmt.Sscanf(value, "%d", &n)

		switch unit {
		case 'h':
			since = time.Now().Add(-time.Duration(n) * time.Hour)
		case 'd':
			since = time.Now().AddDate(0, 0, -n)
		case 'w':
			since = time.Now().AddDate(0, 0, -n*7)
		default:
			since = time.Now().Add(-24 * time.Hour)
		}
	default:
		since = time.Now().Add(-24 * time.Hour)
	}

	fmt.Printf("Collecting events since %s...\n", since.Format("2006-01-02 15:04:05"))

	// Initialize storage
	store, err := storage.NewStorage(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Initialize collector
	coll := collector.NewCollector()

	// Collect events
	events, err := coll.Collect(since)
	if err != nil {
		return fmt.Errorf("collection failed: %w", err)
	}

	// Store events
	if len(events) > 0 {
		if err := store.Add(events); err != nil {
			return fmt.Errorf("failed to store events: %w", err)
		}
	}

	fmt.Printf("Collected %d events\n", len(events))

	// Print summary by type
	byType := make(map[string]int)
	for _, e := range events {
		byType[string(e.Type)]++
	}

	if len(byType) > 0 {
		fmt.Println("\nEvents by type:")
		for t, count := range byType {
			fmt.Printf("  %-25s %d\n", t, count)
		}
	}

	return nil
}

func runExport(cmd *cobra.Command, args []string) error {
	outputPath := args[0]
	cfg := config.DefaultConfig()

	store, err := storage.NewStorage(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}

	if err := store.Export(outputPath); err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	fmt.Printf("Exported %d events to %s\n", store.Count(), outputPath)
	return nil
}

func runImport(cmd *cobra.Command, args []string) error {
	inputPath := args[0]
	cfg := config.DefaultConfig()

	store, err := storage.NewStorage(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}

	countBefore := store.Count()

	if err := store.Import(inputPath); err != nil {
		return fmt.Errorf("import failed: %w", err)
	}

	imported := store.Count() - countBefore
	fmt.Printf("Imported %d events from %s\n", imported, inputPath)
	return nil
}

func runPrune(cmd *cobra.Command, args []string) error {
	days, _ := cmd.Flags().GetInt("days")
	cfg := config.DefaultConfig()

	store, err := storage.NewStorage(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}

	countBefore := store.Count()

	maxAge := time.Duration(days) * 24 * time.Hour
	if err := store.Prune(maxAge); err != nil {
		return fmt.Errorf("prune failed: %w", err)
	}

	pruned := countBefore - store.Count()
	fmt.Printf("Pruned %d events older than %d days\n", pruned, days)
	fmt.Printf("Remaining: %d events\n", store.Count())
	return nil
}
