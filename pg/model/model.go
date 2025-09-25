package model

import (
	"context"
	"time"
)

// UserOrg represents a user or service account
type UserOrg struct {
	ID             string    `json:"id"`
	OrganisationID *string   `json:"organisation_id,omitempty"`
	Username       string    `json:"username"`
	Role           string    `json:"role"`
	UserType       string    `json:"user_type"` // "user" or "service"
	Permissions    []string  `json:"permissions"`
	PasswordHash   string    `json:"-"` // Never expose in JSON
	IsActive       bool      `json:"is_active"`
}

// OrgConfig holds organisation specific auth settings
type OrgConfig struct {
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}


// DB interface defines the contract for database operations required by the auth package.
type DB interface {
	GetUserByUsername(ctx context.Context, username string) (*UserOrg, error)
	GetUserByID(ctx context.Context, userID string) (*UserOrg, error)
	CreateUser(ctx context.Context, user *UserOrg) error
	GetOrgConfig(ctx context.Context, orgID *string) (*OrgConfig, error)
	ValidateUserActive(ctx context.Context, userID string, orgID string) error
	ValidateServiceActive(ctx context.Context, serviceID string) error
}