package pg

import (
	"strings"
	"testing"
)

func TestMigrationFilesAreOrderedAndValid(t *testing.T) {
	list, err := migrations()
	if err != nil {
		t.Fatalf("migrations(): %v", err)
	}
	if len(list) == 0 {
		t.Fatal("expected at least one embedded migration")
	}
	seen := make(map[int64]bool)
	for i, m := range list {
		if i > 0 && m.version <= list[i-1].version {
			t.Errorf("migration %d has version %d; versions must be strictly increasing", i, m.version)
		}
		if seen[m.version] {
			t.Errorf("duplicate migration version %d", m.version)
		}
		seen[m.version] = true
		if m.name == "" {
			t.Errorf("migration %d has an empty name", m.version)
		}
		if strings.TrimSpace(m.stmt) == "" {
			t.Errorf("migration %d (%s) has no SQL", m.version, m.name)
		}
	}
}
