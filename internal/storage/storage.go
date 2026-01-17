package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/afterdarksys/osx-security-timeline/internal/collector"
)

// Storage manages persistent event storage
type Storage struct {
	dataDir string
	events  []*collector.SecurityEvent
}

// NewStorage creates a new storage instance
func NewStorage(dataDir string) (*Storage, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	s := &Storage{
		dataDir: dataDir,
		events:  make([]*collector.SecurityEvent, 0),
	}

	// Load existing events
	if err := s.Load(); err != nil {
		// Ignore load errors for new installations
	}

	return s, nil
}

// Add adds events to storage
func (s *Storage) Add(events []*collector.SecurityEvent) error {
	s.events = append(s.events, events...)
	return s.Save()
}

// GetEvents returns events within a time range
func (s *Storage) GetEvents(start, end time.Time) []*collector.SecurityEvent {
	var result []*collector.SecurityEvent

	for _, event := range s.events {
		if event.Timestamp.After(start) && event.Timestamp.Before(end) {
			result = append(result, event)
		}
	}

	return result
}

// GetAllEvents returns all stored events
func (s *Storage) GetAllEvents() []*collector.SecurityEvent {
	return s.events
}

// Save persists events to disk
func (s *Storage) Save() error {
	// Group events by date for efficient storage
	byDate := make(map[string][]*collector.SecurityEvent)

	for _, event := range s.events {
		dateKey := event.Timestamp.Format("2006-01-02")
		byDate[dateKey] = append(byDate[dateKey], event)
	}

	// Save each date's events to a separate file
	for dateKey, events := range byDate {
		filename := filepath.Join(s.dataDir, fmt.Sprintf("events_%s.json", dateKey))
		data, err := json.MarshalIndent(events, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal events: %w", err)
		}

		if err := os.WriteFile(filename, data, 0644); err != nil {
			return fmt.Errorf("failed to write events file: %w", err)
		}
	}

	return nil
}

// Load loads events from disk
func (s *Storage) Load() error {
	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		return err
	}

	s.events = make([]*collector.SecurityEvent, 0)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		path := filepath.Join(s.dataDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var events []*collector.SecurityEvent
		if err := json.Unmarshal(data, &events); err != nil {
			continue
		}

		s.events = append(s.events, events...)
	}

	return nil
}

// Prune removes events older than the specified duration
func (s *Storage) Prune(maxAge time.Duration) error {
	cutoff := time.Now().Add(-maxAge)

	var kept []*collector.SecurityEvent
	for _, event := range s.events {
		if event.Timestamp.After(cutoff) {
			kept = append(kept, event)
		}
	}

	s.events = kept

	// Also remove old files
	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Parse date from filename
		name := entry.Name()
		if len(name) < 17 { // events_2006-01-02.json
			continue
		}

		dateStr := name[7:17]
		fileDate, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			continue
		}

		if fileDate.Before(cutoff) {
			os.Remove(filepath.Join(s.dataDir, name))
		}
	}

	return s.Save()
}

// Count returns the total number of stored events
func (s *Storage) Count() int {
	return len(s.events)
}

// Snapshot creates a snapshot of current storage state
type Snapshot struct {
	Timestamp time.Time `json:"timestamp"`
	Events    int       `json:"events"`
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
}

// GetSnapshot returns a snapshot of the current storage state
func (s *Storage) GetSnapshot() *Snapshot {
	snapshot := &Snapshot{
		Timestamp: time.Now(),
		Events:    len(s.events),
	}

	if len(s.events) > 0 {
		snapshot.StartDate = s.events[0].Timestamp
		snapshot.EndDate = s.events[len(s.events)-1].Timestamp
	}

	return snapshot
}

// Export exports all events to a single JSON file
func (s *Storage) Export(path string) error {
	data, err := json.MarshalIndent(s.events, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// Import imports events from a JSON file
func (s *Storage) Import(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var events []*collector.SecurityEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return err
	}

	s.events = append(s.events, events...)
	return s.Save()
}
