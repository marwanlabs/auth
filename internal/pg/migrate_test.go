package pg

import (
	"strings"
	"testing"
)

func TestMigrationFilesAreContiguousAndValid(t *testing.T) {
	list, err := migrations()
	if err != nil {
		t.Fatalf("migrations(): %v", err)
	}
	if len(list) == 0 {
		t.Fatal("expected at least one embedded migration")
	}
	seen := make(map[int64]bool)
	for i, m := range list {
		if m.version != int64(i+1) {
			t.Errorf("migration %d has version %d; versions must be contiguous starting at 1", i, m.version)
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

func TestVerifyMigrationVersions(t *testing.T) {
	shipped, err := migrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyMigrationVersions(shipped, []int64{1, 2, 3, 4}); err == nil {
		t.Fatal("expected incomplete migration ledger to be rejected")
	}
	versions := make([]int64, len(shipped))
	for i, m := range shipped {
		versions[i] = m.version
	}
	if err := verifyMigrationVersions(shipped, versions); err != nil {
		t.Fatalf("verifyMigrationVersions: %v", err)
	}
}
