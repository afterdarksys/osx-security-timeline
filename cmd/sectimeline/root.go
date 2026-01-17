package sectimeline

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile    string
	outputJSON bool
)

var rootCmd = &cobra.Command{
	Use:   "sectimeline",
	Short: "macOS Security Timeline",
	Long: `sectimeline - Personal Endpoint Security Timeline

A local-only service that builds a security timeline of your Mac:

  - App installs and uninstalls
  - Permission prompts and grants
  - New binaries appearing
  - Network access grants
  - USB device insertions
  - Launch agent/daemon changes
  - Login/logout events
  - System updates

Then lets you ask questions like:

  "What changed right before my mic turned on?"
  "What was installed last week?"
  "Show me all permission changes today"

macOS logs are unreadable. sectimeline makes them useful.`,
	Version: "1.0.0",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ~/.config/sectimeline/config.yaml)")
	rootCmd.PersistentFlags().BoolVar(&outputJSON, "json", false, "output in JSON format")
}
