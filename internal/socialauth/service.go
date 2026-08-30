package socialauth

import (
	"strings"
	"time"

	"authserver/internal/auth"
	"authserver/internal/providers"
	"authserver/internal/store"
)

type Repository interface {
	GetIdentity(provider, subject string) (*store.SocialIdentity, error)
	GetUserByID(id string) (*store.User, error)
	GetUserByEmail(email string) (*store.User, error)
	CountUsers() int
	CreateUser(*store.User) error
	CreateIdentity(*store.SocialIdentity) error
}

type Service struct{ repository Repository }

func New(repository Repository) *Service { return &Service{repository: repository} }

func (s *Service) Resolve(identity providers.Identity) (*store.User, error) {
	linked, err := s.repository.GetIdentity(identity.Provider, identity.Subject)
	if err == nil {
		return s.repository.GetUserByID(linked.UserID)
	}
	if err != store.ErrNotFound {
		return nil, err
	}
	u, err := s.repository.GetUserByEmail(normalizeEmail(identity.Email))
	if err == store.ErrNotFound {
		role := store.RoleUser
		if s.repository.CountUsers() == 0 {
			role = store.RoleAdmin
		}
		u = &store.User{ID: mustID(), Email: normalizeEmail(identity.Email), Role: role, CreatedAt: time.Now()}
		if err = s.repository.CreateUser(u); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if err := s.repository.CreateIdentity(&store.SocialIdentity{ID: mustID(), Provider: identity.Provider, Subject: identity.Subject, UserID: u.ID, CreatedAt: time.Now()}); err != nil && err != store.ErrConflict {
		return nil, err
	}
	return u, nil
}

func normalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func mustID() string {
	id, err := auth.NewToken(16)
	if err != nil {
		panic("socialauth: failed to generate id: " + err.Error())
	}
	return id
}
