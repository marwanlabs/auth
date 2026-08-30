package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAuditEventsPersistAcrossOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	want := &AuditEvent{
		ID: "event-1", Type: "login", Outcome: "failure", Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		ActorEmail: "person@example.com", ClientIP: "192.0.2.1", UserAgent: "test-agent",
	}
	if err := s.CreateAuditEvent(want); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.d.AuditEvents[want.ID]; *got != *want {
		t.Fatalf("persisted event = %+v, want %+v", got, want)
	}
}
