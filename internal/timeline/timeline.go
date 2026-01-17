package timeline

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/afterdarksys/osx-security-timeline/internal/collector"
)

// Timeline represents a security event timeline
type Timeline struct {
	Events    []*collector.SecurityEvent `json:"events"`
	StartTime time.Time                   `json:"start_time"`
	EndTime   time.Time                   `json:"end_time"`
	Summary   *TimelineSummary            `json:"summary"`
}

// TimelineSummary provides summary statistics
type TimelineSummary struct {
	TotalEvents     int            `json:"total_events"`
	EventsByType    map[string]int `json:"events_by_type"`
	HighRiskEvents  int            `json:"high_risk_events"`
	TopActors       []string       `json:"top_actors"`
	ActivityPeaks   []time.Time    `json:"activity_peaks"`
}

// NewTimeline creates a new timeline from events
func NewTimeline(events []*collector.SecurityEvent) *Timeline {
	if len(events) == 0 {
		return &Timeline{
			Events:  events,
			Summary: &TimelineSummary{EventsByType: make(map[string]int)},
		}
	}

	// Sort events by timestamp
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	tl := &Timeline{
		Events:    events,
		StartTime: events[0].Timestamp,
		EndTime:   events[len(events)-1].Timestamp,
	}

	tl.Summary = tl.generateSummary()
	return tl
}

// generateSummary generates summary statistics
func (tl *Timeline) generateSummary() *TimelineSummary {
	summary := &TimelineSummary{
		TotalEvents:  len(tl.Events),
		EventsByType: make(map[string]int),
	}

	actorCount := make(map[string]int)

	for _, event := range tl.Events {
		// Count by type
		summary.EventsByType[string(event.Type)]++

		// Count high risk
		if event.RiskScore >= 70 {
			summary.HighRiskEvents++
		}

		// Count actors
		if event.Actor != "" {
			actorCount[event.Actor]++
		}
	}

	// Get top actors
	type actorStat struct {
		name  string
		count int
	}
	var actors []actorStat
	for name, count := range actorCount {
		actors = append(actors, actorStat{name, count})
	}
	sort.Slice(actors, func(i, j int) bool {
		return actors[i].count > actors[j].count
	})

	for i, a := range actors {
		if i >= 5 {
			break
		}
		summary.TopActors = append(summary.TopActors, a.name)
	}

	return summary
}

// Filter filters events by criteria
func (tl *Timeline) Filter(criteria FilterCriteria) *Timeline {
	var filtered []*collector.SecurityEvent

	for _, event := range tl.Events {
		if criteria.Matches(event) {
			filtered = append(filtered, event)
		}
	}

	return NewTimeline(filtered)
}

// FilterCriteria defines event filtering criteria
type FilterCriteria struct {
	Types     []collector.EventType
	After     time.Time
	Before    time.Time
	Actor     string
	Target    string
	MinRisk   int
	SearchStr string
}

// Matches checks if an event matches the criteria
func (fc *FilterCriteria) Matches(event *collector.SecurityEvent) bool {
	// Type filter
	if len(fc.Types) > 0 {
		found := false
		for _, t := range fc.Types {
			if event.Type == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Time filters
	if !fc.After.IsZero() && event.Timestamp.Before(fc.After) {
		return false
	}
	if !fc.Before.IsZero() && event.Timestamp.After(fc.Before) {
		return false
	}

	// Actor filter
	if fc.Actor != "" && !strings.Contains(strings.ToLower(event.Actor), strings.ToLower(fc.Actor)) {
		return false
	}

	// Target filter
	if fc.Target != "" && !strings.Contains(strings.ToLower(event.Target), strings.ToLower(fc.Target)) {
		return false
	}

	// Risk filter
	if fc.MinRisk > 0 && event.RiskScore < fc.MinRisk {
		return false
	}

	// Search string
	if fc.SearchStr != "" {
		searchLower := strings.ToLower(fc.SearchStr)
		if !strings.Contains(strings.ToLower(event.Description), searchLower) &&
			!strings.Contains(strings.ToLower(event.Actor), searchLower) &&
			!strings.Contains(strings.ToLower(event.Target), searchLower) {
			return false
		}
	}

	return true
}

// Query performs a natural language query on the timeline
func (tl *Timeline) Query(query string) (*Timeline, string) {
	queryLower := strings.ToLower(query)

	// Parse query for time references
	var after, before time.Time
	now := time.Now()

	if strings.Contains(queryLower, "today") {
		after = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	} else if strings.Contains(queryLower, "yesterday") {
		yesterday := now.AddDate(0, 0, -1)
		after = time.Date(yesterday.Year(), yesterday.Month(), yesterday.Day(), 0, 0, 0, 0, now.Location())
		before = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	} else if strings.Contains(queryLower, "last hour") {
		after = now.Add(-1 * time.Hour)
	} else if strings.Contains(queryLower, "last week") {
		after = now.AddDate(0, 0, -7)
	}

	// Parse query for event types
	var types []collector.EventType
	if strings.Contains(queryLower, "permission") {
		types = append(types, collector.EventPermissionGrant, collector.EventPermissionUse)
	}
	if strings.Contains(queryLower, "install") {
		types = append(types, collector.EventAppInstall)
	}
	if strings.Contains(queryLower, "camera") || strings.Contains(queryLower, "mic") {
		types = append(types, collector.EventPermissionUse)
	}
	if strings.Contains(queryLower, "usb") {
		types = append(types, collector.EventUSBInsert, collector.EventUSBRemove)
	}
	if strings.Contains(queryLower, "network") {
		types = append(types, collector.EventNetworkAccess)
	}
	if strings.Contains(queryLower, "launch") {
		types = append(types, collector.EventLaunchAgent, collector.EventLaunchDaemon)
	}

	criteria := FilterCriteria{
		Types:  types,
		After:  after,
		Before: before,
	}

	filtered := tl.Filter(criteria)

	// Generate response
	response := fmt.Sprintf("Found %d events", len(filtered.Events))
	if !after.IsZero() {
		response += fmt.Sprintf(" since %s", after.Format("2006-01-02 15:04"))
	}
	if len(types) > 0 {
		response += fmt.Sprintf(" matching types: %v", types)
	}

	return filtered, response
}

// Around returns events around a specific time
func (tl *Timeline) Around(t time.Time, window time.Duration) *Timeline {
	criteria := FilterCriteria{
		After:  t.Add(-window),
		Before: t.Add(window),
	}
	return tl.Filter(criteria)
}

// Diff compares two timelines and returns differences
func (tl *Timeline) Diff(other *Timeline) *TimelineDiff {
	diff := &TimelineDiff{
		OnlyInFirst:  make([]*collector.SecurityEvent, 0),
		OnlyInSecond: make([]*collector.SecurityEvent, 0),
	}

	// Build map of events by ID
	firstMap := make(map[string]*collector.SecurityEvent)
	for _, e := range tl.Events {
		firstMap[e.ID] = e
	}

	secondMap := make(map[string]*collector.SecurityEvent)
	for _, e := range other.Events {
		secondMap[e.ID] = e
	}

	// Find differences
	for id, e := range firstMap {
		if _, ok := secondMap[id]; !ok {
			diff.OnlyInFirst = append(diff.OnlyInFirst, e)
		}
	}

	for id, e := range secondMap {
		if _, ok := firstMap[id]; !ok {
			diff.OnlyInSecond = append(diff.OnlyInSecond, e)
		}
	}

	return diff
}

// TimelineDiff represents differences between two timelines
type TimelineDiff struct {
	OnlyInFirst  []*collector.SecurityEvent `json:"only_in_first"`
	OnlyInSecond []*collector.SecurityEvent `json:"only_in_second"`
}

// ToJSON converts timeline to JSON
func (tl *Timeline) ToJSON() ([]byte, error) {
	return json.MarshalIndent(tl, "", "  ")
}

// FormatEvent formats a single event for display
func FormatEvent(event *collector.SecurityEvent) string {
	riskIcon := "⚪"
	if event.RiskScore >= 70 {
		riskIcon = "🔴"
	} else if event.RiskScore >= 40 {
		riskIcon = "🟡"
	} else if event.RiskScore >= 20 {
		riskIcon = "🟢"
	}

	return fmt.Sprintf("%s %s [%s] %s",
		event.Timestamp.Format("2006-01-02 15:04:05"),
		riskIcon,
		event.Type,
		event.Description)
}
