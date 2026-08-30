package store_test

import (
	"path/filepath"
	"testing"
	"time"

	"authserver/internal/store"
)

func TestAuditEventsPersistAcrossOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	want := &store.AuditEvent{
		ID: "event-1", Type: "login", Outcome: "failure", Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		ActorEmail: "person@example.com", Target: "user-9", ClientIP: "192.0.2.1", UserAgent: "test-agent",
	}
	if err := s.CreateAuditEvent(want); err != nil {
		t.Fatal(err)
	}

	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var got *store.AuditEvent
	for _, event := range reopened.ListAuditEvents() {
		if event.ID == want.ID {
			got = event
		}
	}
	if got == nil || *got != *want {
		t.Fatalf("persisted event = %+v, want %+v", got, want)
	}
}
