package store_test

import (
	"testing"

	"authserver/internal/store"
	"authserver/internal/store/contract"
)

func TestJSONStoreRepositoryContract(t *testing.T) {
	contract.Run(t, func(t *testing.T) contract.Repository {
		s, err := store.Open(t.TempDir() + "/store.json")
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestJSONStoreDurableReopen(t *testing.T) {
	path := t.TempDir() + "/store.json"
	contract.RunDurability(t, func() contract.Repository {
		s, err := store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestJSONStoreAuditContract(t *testing.T) {
	contract.RunAudit(t, func(t *testing.T) contract.AuditRepository {
		s, err := store.Open(t.TempDir() + "/store.json")
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestJSONStoreAuditDurability(t *testing.T) {
	path := t.TempDir() + "/store.json"
	contract.RunAuditDurability(t, func() contract.AuditRepository {
		s, err := store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}
