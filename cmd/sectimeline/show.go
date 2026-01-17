package sectimeline

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/afterdarksys/osx-security-timeline/internal/collector"
	"github.com/afterdarksys/osx-security-timeline/internal/config"
	"github.com/afterdarksys/osx-security-timeline/internal/storage"
	"github.com/afterdarksys/osx-security-timeline/internal/timeline"
	"github.com/spf13/cobra"
)

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Show security timeline",
	Long:  `Display the security event timeline with optional filters.`,
	RunE:  runShow,
}

var queryCmd = &cobra.Command{
	Use:   "query [question]",
	Short: "Query the timeline",
	Long: `Ask a natural language question about security events.

Examples:
  sectimeline query "What changed today?"
  sectimeline query "Show permission changes"
  sectimeline query "What happened last week?"
  sectimeline query "What was installed yesterday?"`,
	Args: cobra.ExactArgs(1),
	RunE: runQuery,
}

var summaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Show timeline summary",
	Long:  `Display a summary of security events.`,
	RunE:  runSummary,
}

func init() {
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(queryCmd)
	rootCmd.AddCommand(summaryCmd)

	showCmd.Flags().StringP("since", "s", "24h", "show events since (e.g., 1h, 24h, 7d)")
	showCmd.Flags().StringP("type", "t", "", "filter by event type")
	showCmd.Flags().IntP("limit", "n", 50, "maximum events to show")
}

func runShow(cmd *cobra.Command, args []string) error {
	sinceStr, _ := cmd.Flags().GetString("since")
	eventType, _ := cmd.Flags().GetString("type")
	limit, _ := cmd.Flags().GetInt("limit")

	cfg := config.DefaultConfig()

	// Parse since duration
	var since time.Time
	switch {
	case sinceStr == "today":
		now := time.Now()
		since = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	case len(sinceStr) > 1:
		// Parse duration like "24h", "7d"
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

	// Try daemon first
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/events?since=%s", cfg.HTTPPort, since.Format(time.RFC3339)))
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		var events []*collector.SecurityEvent
		json.Unmarshal(body, &events)

		if outputJSON {
			fmt.Println(string(body))
			return nil
		}

		printEvents(events, eventType, limit)
		return nil
	}

	// Fall back to direct storage access
	store, err := storage.NewStorage(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}

	events := store.GetEvents(since, time.Now())

	if outputJSON {
		data, _ := json.MarshalIndent(events, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	printEvents(events, eventType, limit)
	return nil
}

func printEvents(events []*collector.SecurityEvent, typeFilter string, limit int) {
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                    SECURITY TIMELINE                           ")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	if len(events) == 0 {
		fmt.Println("No events found.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tTYPE\tDESCRIPTION")
	fmt.Fprintln(w, "────\t────\t───────────")

	count := 0
	for i := len(events) - 1; i >= 0 && count < limit; i-- {
		event := events[i]

		if typeFilter != "" && string(event.Type) != typeFilter {
			continue
		}

		riskIcon := getRiskIcon(event.RiskScore)
		fmt.Fprintf(w, "%s\t%s %s\t%s\n",
			event.Timestamp.Format("01-02 15:04"),
			riskIcon,
			event.Type,
			truncate(event.Description, 50))
		count++
	}
	w.Flush()

	fmt.Printf("\nShowing %d of %d events\n", count, len(events))
}

func runQuery(cmd *cobra.Command, args []string) error {
	query := args[0]
	cfg := config.DefaultConfig()

	// Try daemon first
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/query?q=%s", cfg.HTTPPort, query))
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if outputJSON {
			fmt.Println(string(body))
			return nil
		}

		var result map[string]interface{}
		json.Unmarshal(body, &result)

		response, _ := result["response"].(string)
		fmt.Println(response)
		fmt.Println()

		if events, ok := result["events"].([]interface{}); ok {
			fmt.Printf("Found %d events:\n\n", len(events))
			for i, e := range events {
				if i >= 20 {
					fmt.Printf("... and %d more\n", len(events)-20)
					break
				}
				if event, ok := e.(map[string]interface{}); ok {
					ts, _ := event["timestamp"].(string)
					desc, _ := event["description"].(string)
					eventType, _ := event["type"].(string)
					fmt.Printf("  %s [%s] %s\n", ts[:19], eventType, truncate(desc, 50))
				}
			}
		}
		return nil
	}

	// Fall back to direct access
	store, err := storage.NewStorage(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}

	events := store.GetAllEvents()
	tl := timeline.NewTimeline(events)
	result, response := tl.Query(query)

	fmt.Println(response)
	fmt.Println()

	for i, event := range result.Events {
		if i >= 20 {
			fmt.Printf("... and %d more\n", len(result.Events)-20)
			break
		}
		fmt.Println(timeline.FormatEvent(event))
	}

	return nil
}

func runSummary(cmd *cobra.Command, args []string) error {
	cfg := config.DefaultConfig()

	// Try daemon first
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/summary", cfg.HTTPPort))
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if outputJSON {
			fmt.Println(string(body))
			return nil
		}

		var summary timeline.TimelineSummary
		json.Unmarshal(body, &summary)

		printSummary(&summary)
		return nil
	}

	// Fall back to direct access
	store, err := storage.NewStorage(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}

	events := store.GetAllEvents()
	tl := timeline.NewTimeline(events)

	if outputJSON {
		data, _ := json.MarshalIndent(tl.Summary, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	printSummary(tl.Summary)
	return nil
}

func printSummary(summary *timeline.TimelineSummary) {
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                    TIMELINE SUMMARY                            ")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintf(w, "Total Events:\t%d\n", summary.TotalEvents)
	fmt.Fprintf(w, "High Risk Events:\t%d\n", summary.HighRiskEvents)
	w.Flush()

	fmt.Println()
	fmt.Println("Events by Type:")
	for eventType, count := range summary.EventsByType {
		fmt.Printf("  %-25s %d\n", eventType, count)
	}

	if len(summary.TopActors) > 0 {
		fmt.Println()
		fmt.Println("Top Actors:")
		for _, actor := range summary.TopActors {
			fmt.Printf("  %s\n", actor)
		}
	}
}

func getRiskIcon(score int) string {
	switch {
	case score >= 70:
		return "🔴"
	case score >= 40:
		return "🟡"
	case score >= 20:
		return "🟢"
	default:
		return "⚪"
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
