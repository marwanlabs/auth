package socialauth

import (
	"errors"
	"testing"

	"authserver/internal/providers"
	"authserver/internal/store"
)

type repositoryStub struct {
	identities map[string]*store.SocialIdentity
	users      map[string]*store.User
	count      int
	createErr  error
}

func (r *repositoryStub) GetIdentity(provider, subject string) (*store.SocialIdentity, error) {
	i, ok := r.identities[provider+":"+subject]
	if !ok {
		return nil, store.ErrNotFound
	}
	return i, nil
}
func (r *repositoryStub) GetUserByID(id string) (*store.User, error) {
	u, ok := r.users[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return u, nil
}
func (r *repositoryStub) GetUserByEmail(email string) (*store.User, error) {
	for _, u := range r.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, store.ErrNotFound
}
func (r *repositoryStub) CountUsers() int { return r.count }
func (r *repositoryStub) CreateUser(u *store.User) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.users[u.ID] = u
	r.count++
	return nil
}
func (r *repositoryStub) CreateIdentity(i *store.SocialIdentity) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.identities[i.Provider+":"+i.Subject] = i
	return nil
}

func identity() providers.Identity {
	return providers.Identity{Provider: "github", Subject: "sub-1", Email: " User@Example.COM ", EmailVerified: true}
}

func TestResolveLinksExistingIdentity(t *testing.T) {
	r := &repositoryStub{identities: map[string]*store.SocialIdentity{"github:sub-1": {UserID: "user-1"}}, users: map[string]*store.User{"user-1": {ID: "user-1", Email: "user@example.com"}}}
	got, err := New(r).Resolve(identity())
	if err != nil || got.ID != "user-1" {
		t.Fatalf("resolved user: %v, %v", got, err)
	}
}

func TestResolveLinksNewIdentityToExistingEmail(t *testing.T) {
	r := &repositoryStub{identities: map[string]*store.SocialIdentity{}, users: map[string]*store.User{"user-1": {ID: "user-1", Email: "user@example.com"}}, count: 1}
	got, err := New(r).Resolve(identity())
	if err != nil || got.ID != "user-1" {
		t.Fatalf("resolved user: %v, %v", got, err)
	}
	if _, ok := r.identities["github:sub-1"]; !ok {
		t.Fatal("identity was not created")
	}
}

func TestResolveCreatesFirstAdmin(t *testing.T) {
	r := &repositoryStub{identities: map[string]*store.SocialIdentity{}, users: map[string]*store.User{}}
	got, err := New(r).Resolve(identity())
	if err != nil || got.Role != store.RoleAdmin || got.Email != "user@example.com" {
		t.Fatalf("new user: %v, %v", got, err)
	}
}

func TestResolvePropagatesRepositoryError(t *testing.T) {
	want := errors.New("database unavailable")
	r := &repositoryStub{identities: map[string]*store.SocialIdentity{}, users: map[string]*store.User{}, createErr: want}
	if _, err := New(r).Resolve(identity()); !errors.Is(err, want) {
		t.Fatalf("error = %v", err)
	}
}
