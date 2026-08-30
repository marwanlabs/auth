package auth

import "authserver/internal/store"

// Repository contains the persistence capabilities needed by authentication
// middleware and session creation.
type Repository interface {
	CreateSession(*store.Session) error
	GetSession(string) (*store.Session, error)
	GetUserByID(string) (*store.User, error)
}
