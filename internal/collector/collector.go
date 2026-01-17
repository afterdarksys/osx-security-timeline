package collector

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// EventType represents the type of security event
type EventType string

const (
	EventAppInstall      EventType = "app_install"
	EventAppUninstall    EventType = "app_uninstall"
	EventAppLaunch       EventType = "app_launch"
	EventPermissionGrant EventType = "permission_grant"
	EventPermissionUse   EventType = "permission_use"
	EventNewBinary       EventType = "new_binary"
	EventBinaryModified  EventType = "binary_modified"
	EventNetworkAccess   EventType = "network_access"
	EventUSBInsert       EventType = "usb_insert"
	EventUSBRemove       EventType = "usb_remove"
	EventLoginItem       EventType = "login_item"
	EventLaunchAgent     EventType = "launch_agent"
	EventLaunchDaemon    EventType = "launch_daemon"
	EventSystemBoot      EventType = "system_boot"
	EventUserLogin       EventType = "user_login"
	EventUserLogout      EventType = "user_logout"
	EventScreenLock      EventType = "screen_lock"
	EventScreenUnlock    EventType = "screen_unlock"
	EventFirewallChange  EventType = "firewall_change"
	EventGatekeeper      EventType = "gatekeeper"
	EventXProtect        EventType = "xprotect"
	EventSystemUpdate    EventType = "system_update"
)

// SecurityEvent represents a security-relevant event
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        EventType              `json:"type"`
	Source      string                 `json:"source"`
	Actor       string                 `json:"actor,omitempty"`
	Target      string                 `json:"target,omitempty"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details,omitempty"`
	RiskScore   int                    `json:"risk_score"`
}

// Collector collects security events from various sources
type Collector struct {
	events     []*SecurityEvent
	maxEvents  int
	sources    []EventSource
}

// EventSource is an interface for event sources
type EventSource interface {
	Name() string
	Collect(since time.Time) ([]*SecurityEvent, error)
}

// NewCollector creates a new event collector
func NewCollector() *Collector {
	c := &Collector{
		events:    make([]*SecurityEvent, 0),
		maxEvents: 100000,
		sources:   make([]EventSource, 0),
	}

	// Register built-in sources
	c.sources = append(c.sources, &UnifiedLogSource{})
	c.sources = append(c.sources, &InstallHistorySource{})
	c.sources = append(c.sources, &SystemPrefsSource{})
	c.sources = append(c.sources, &LaunchItemSource{})

	return c
}

// Collect collects events from all sources since the given time
func (c *Collector) Collect(since time.Time) ([]*SecurityEvent, error) {
	var allEvents []*SecurityEvent

	for _, source := range c.sources {
		events, err := source.Collect(since)
		if err != nil {
			continue // Log error but continue
		}
		allEvents = append(allEvents, events...)
	}

	// Sort by timestamp
	sortEvents(allEvents)

	return allEvents, nil
}

// UnifiedLogSource collects events from the unified log
type UnifiedLogSource struct{}

func (u *UnifiedLogSource) Name() string { return "unified_log" }

func (u *UnifiedLogSource) Collect(since time.Time) ([]*SecurityEvent, error) {
	var events []*SecurityEvent

	// Query unified log for security-relevant events
	sinceStr := since.Format("2006-01-02 15:04:05")

	// TCC (permission) events
	cmd := exec.Command("log", "show",
		"--predicate", `subsystem == "com.apple.TCC"`,
		"--start", sinceStr,
		"--style", "json",
		"--info")
	output, err := cmd.Output()
	if err == nil {
		events = append(events, parseUnifiedLog(output, EventPermissionGrant)...)
	}

	// Gatekeeper events
	cmd = exec.Command("log", "show",
		"--predicate", `subsystem == "com.apple.syspolicyd"`,
		"--start", sinceStr,
		"--style", "json",
		"--info")
	output, err = cmd.Output()
	if err == nil {
		events = append(events, parseUnifiedLog(output, EventGatekeeper)...)
	}

	// XProtect events
	cmd = exec.Command("log", "show",
		"--predicate", `subsystem == "com.apple.xprotect"`,
		"--start", sinceStr,
		"--style", "json",
		"--info")
	output, err = cmd.Output()
	if err == nil {
		events = append(events, parseUnifiedLog(output, EventXProtect)...)
	}

	// Login/logout events
	cmd = exec.Command("log", "show",
		"--predicate", `eventMessage CONTAINS "login" OR eventMessage CONTAINS "logout"`,
		"--start", sinceStr,
		"--style", "json",
		"--info")
	output, err = cmd.Output()
	if err == nil {
		events = append(events, parseUnifiedLog(output, EventUserLogin)...)
	}

	return events, nil
}

func parseUnifiedLog(data []byte, defaultType EventType) []*SecurityEvent {
	var events []*SecurityEvent
	var logEntries []map[string]interface{}

	if err := json.Unmarshal(data, &logEntries); err != nil {
		return events
	}

	for _, entry := range logEntries {
		event := &SecurityEvent{
			ID:      fmt.Sprintf("log_%d", time.Now().UnixNano()),
			Type:    defaultType,
			Source:  "unified_log",
			Details: entry,
		}

		// Parse timestamp
		if ts, ok := entry["timestamp"].(string); ok {
			event.Timestamp, _ = time.Parse(time.RFC3339, ts)
		}

		// Parse message
		if msg, ok := entry["eventMessage"].(string); ok {
			event.Description = msg
		}

		// Parse subsystem
		if sub, ok := entry["subsystem"].(string); ok {
			event.Actor = sub
		}

		events = append(events, event)
	}

	return events
}

// InstallHistorySource collects app install events
type InstallHistorySource struct{}

func (i *InstallHistorySource) Name() string { return "install_history" }

func (i *InstallHistorySource) Collect(since time.Time) ([]*SecurityEvent, error) {
	var events []*SecurityEvent

	// Read install history plist
	historyPath := "/Library/Receipts/InstallHistory.plist"
	cmd := exec.Command("plutil", "-convert", "json", "-o", "-", historyPath)
	output, err := cmd.Output()
	if err != nil {
		return events, err
	}

	var history []map[string]interface{}
	if err := json.Unmarshal(output, &history); err != nil {
		return events, err
	}

	for _, entry := range history {
		// Parse date
		dateStr, _ := entry["date"].(string)
		installDate, err := time.Parse("2006-01-02T15:04:05Z", dateStr)
		if err != nil {
			continue
		}

		if installDate.Before(since) {
			continue
		}

		pkgName, _ := entry["displayName"].(string)
		pkgVersion, _ := entry["displayVersion"].(string)
		processName, _ := entry["processName"].(string)

		event := &SecurityEvent{
			ID:          fmt.Sprintf("install_%d", installDate.UnixNano()),
			Timestamp:   installDate,
			Type:        EventAppInstall,
			Source:      "install_history",
			Actor:       processName,
			Target:      pkgName,
			Description: fmt.Sprintf("Installed %s %s", pkgName, pkgVersion),
			Details: map[string]interface{}{
				"package": pkgName,
				"version": pkgVersion,
				"process": processName,
			},
		}

		events = append(events, event)
	}

	return events, nil
}

// SystemPrefsSource collects system preference changes
type SystemPrefsSource struct{}

func (s *SystemPrefsSource) Name() string { return "system_prefs" }

func (s *SystemPrefsSource) Collect(since time.Time) ([]*SecurityEvent, error) {
	var events []*SecurityEvent

	// Check security preferences
	homeDir, _ := os.UserHomeDir()

	// Check for recent TCC database modifications
	tccPath := filepath.Join(homeDir, "Library/Application Support/com.apple.TCC/TCC.db")
	if info, err := os.Stat(tccPath); err == nil {
		if info.ModTime().After(since) {
			events = append(events, &SecurityEvent{
				ID:          fmt.Sprintf("tcc_%d", info.ModTime().UnixNano()),
				Timestamp:   info.ModTime(),
				Type:        EventPermissionGrant,
				Source:      "tcc_database",
				Description: "TCC database modified (permission change)",
				Details: map[string]interface{}{
					"file": tccPath,
				},
			})
		}
	}

	return events, nil
}

// LaunchItemSource collects launch agent/daemon changes
type LaunchItemSource struct{}

func (l *LaunchItemSource) Name() string { return "launch_items" }

func (l *LaunchItemSource) Collect(since time.Time) ([]*SecurityEvent, error) {
	var events []*SecurityEvent

	homeDir, _ := os.UserHomeDir()

	// Check directories for new/modified items
	dirs := []struct {
		path      string
		eventType EventType
	}{
		{filepath.Join(homeDir, "Library/LaunchAgents"), EventLaunchAgent},
		{"/Library/LaunchAgents", EventLaunchAgent},
		{"/Library/LaunchDaemons", EventLaunchDaemon},
	}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir.path)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".plist") {
				continue
			}

			fullPath := filepath.Join(dir.path, entry.Name())
			info, err := entry.Info()
			if err != nil {
				continue
			}

			if info.ModTime().After(since) {
				label := strings.TrimSuffix(entry.Name(), ".plist")
				events = append(events, &SecurityEvent{
					ID:          fmt.Sprintf("launch_%d", info.ModTime().UnixNano()),
					Timestamp:   info.ModTime(),
					Type:        dir.eventType,
					Source:      "launch_items",
					Target:      fullPath,
					Description: fmt.Sprintf("Launch item modified: %s", label),
					Details: map[string]interface{}{
						"label": label,
						"path":  fullPath,
					},
					RiskScore: 30,
				})
			}
		}
	}

	return events, nil
}

// sortEvents sorts events by timestamp
func sortEvents(events []*SecurityEvent) {
	// Simple bubble sort for now
	for i := 0; i < len(events); i++ {
		for j := i + 1; j < len(events); j++ {
			if events[j].Timestamp.Before(events[i].Timestamp) {
				events[i], events[j] = events[j], events[i]
			}
		}
	}
}

// CollectUSBEvents collects USB insertion/removal events
func CollectUSBEvents(since time.Time) ([]*SecurityEvent, error) {
	var events []*SecurityEvent

	// Use system_profiler to get USB info
	cmd := exec.Command("system_profiler", "SPUSBDataType", "-json")
	output, err := cmd.Output()
	if err != nil {
		return events, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(output, &data); err != nil {
		return events, err
	}

	// Parse USB devices (simplified)
	// In production, would compare against baseline

	return events, nil
}

// CollectNetworkEvents collects network-related events
func CollectNetworkEvents(since time.Time) ([]*SecurityEvent, error) {
	var events []*SecurityEvent

	// Check firewall state changes
	cmd := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	if output, err := cmd.Output(); err == nil {
		// Parse firewall state
		_ = output
	}

	// Check for new network connections from logs
	cmd = exec.Command("log", "show",
		"--predicate", `subsystem == "com.apple.network"`,
		"--start", since.Format("2006-01-02 15:04:05"),
		"--info")
	if output, err := cmd.Output(); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "connection") {
				events = append(events, &SecurityEvent{
					ID:          fmt.Sprintf("net_%d", time.Now().UnixNano()),
					Timestamp:   time.Now(),
					Type:        EventNetworkAccess,
					Source:      "network_log",
					Description: line,
				})
			}
		}
	}

	return events, nil
}
