package sectimeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/afterdarksys/afterdark-darkd/pkg/journal"
	"github.com/spf13/cobra"
)

var journalDB string
var journalLimit int

var journalCmd = &cobra.Command{
	Use:   "journal",
	Short: "Read the darkd event journal",
	Long:  "Show process, file, DNS, and flow events from the endpoint journal. An empty or partial read is not a clean host.",
	RunE: func(cmd *cobra.Command, args []string) error {
		reader, err := journal.Open(journalDB)
		if err != nil {
			return err
		}
		defer reader.Close()
		records, err := reader.List(context.Background(), journal.Query{Types: journal.SensorTypes, Limit: journalLimit})
		if err != nil {
			return err
		}
		summary := journal.Summarize(records)
		if outputJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{"summary": summary, "records": records})
		}
		fmt.Printf("complete=%t enforced=%t count=%d %s\n", summary.Complete, summary.Enforced, summary.Count, summary.Limitation)
		for _, rec := range records {
			fmt.Printf("%s %s %s %s\n", rec.Time.Format(time.RFC3339), rec.CollectionStatus, rec.Source, rec.Type)
		}
		return nil
	},
}

func init() {
	journalCmd.Flags().StringVar(&journalDB, "db", journal.DefaultPath(), "darkd event journal")
	journalCmd.Flags().IntVar(&journalLimit, "limit", 100, "maximum events")
	rootCmd.AddCommand(journalCmd)
}
