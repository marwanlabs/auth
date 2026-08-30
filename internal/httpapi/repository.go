package httpapi

import "authserver/internal/store"

type UserRepository interface {
	CreateUser(*store.User) error
	GetUserByID(string) (*store.User, error)
	GetUserByEmail(string) (*store.User, error)
	UpdateUser(*store.User) error
	DeleteUser(string) error
	CountUsers() int
	CountAdmins() int
	ListUsers() []*store.User
}

type SessionRepository interface {
	GetSession(string) (*store.Session, error)
	DeleteSession(string) error
	ListSessionsForUser(string) ([]*store.Session, error)
}

type ResetTokenRepository interface {
	CreateResetToken(*store.ResetToken) error
	GetResetToken(string) (*store.ResetToken, error)
	DeleteResetToken(string) error
}

type ProviderRepository interface {
	ListProviderSettings() map[string]bool
	ProviderSetting(string) (bool, bool)
	SetProviderEnabled(string, bool) error
}
