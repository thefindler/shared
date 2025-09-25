package auth

import (
	"context"
	"time"
	"github.com/golang-jwt/jwt/v5"
)

type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

// User represents a user or service account
type User struct {
	ID             string    `json:"id"`
	OrganisationID *string   `json:"organisation_id,omitempty"`
	Username       string    `json:"username"`
	Role           string    `json:"role"`
	UserType       string    `json:"user_type"` // "user" or "service"
	Permissions    []string  `json:"permissions"`
	PasswordHash   string    `json:"-"` // Never expose in JSON
	IsActive       bool      `json:"is_active"`
}

// Claims for JWT tokens
type Claims struct {
	UserID         string    `json:"user_id"`
	OrganisationID *string   `json:"organisation_id,omitempty"`
	Username       string    `json:"username"`
	Role           string    `json:"role"`
	UserType       string    `json:"user_type"`
	Permissions    []string  `json:"permissions"`
	TokenType      TokenType `json:"token_type"`
	jwt.RegisteredClaims
}

// AuthContext for validated requests
type AuthContext struct {
	UserID         string   `json:"user_id"`
	OrganisationID *string  `json:"organisation_id,omitempty"`
	Username       string   `json:"username"`
	Role           string   `json:"role"`
	UserType       string   `json:"user_type"`
	Permissions    []string `json:"permissions"`
}

// OrgConfig holds organisation specific auth settings
type OrgConfig struct {
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	JWTSecret       string
}


// Simple DB interface - only what we need
type DB interface {
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByID(ctx context.Context, userID string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
	IsTokenDenied(ctx context.Context, jti string) (bool, error)
	DenyToken(ctx context.Context, jti string, expiresAt time.Time) error
	GetOrgConfig(ctx context.Context, orgID *string) (*OrgConfig, error)
}

// UserValidator defines the interface for user validation.
type UserValidator interface {
	ValidateUserActive(ctx context.Context, userID string, orgID string) error
}

// ServiceValidator defines the interface for service account validation.
type ServiceValidator interface {
	ValidateServiceActive(ctx context.Context, serviceID string) error
}

// AuthRequirement specifies what authorization is needed for an endpoint.
// An empty struct means any authenticated user is allowed.
type AuthRequirement struct {
	RequiredRoles       []string
	RequiredPermissions []string
}