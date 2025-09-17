package auth

import (
	"github.com/golang-jwt/jwt/v5"
)

// TokenType represents the type of JWT token
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

// UserClaims represents claims for all tokens (users and services)
// Services are treated as special users with user_type="service"
type UserClaims struct {
	UserID         string    `json:"user_id"`         // User UUID or Service UUID
	OrganisationID *string   `json:"organisation_id"` // NULL for global services
	Username       string    `json:"username"`        // Username or service name
	Role           string    `json:"role"`            // 'admin', 'agent-manager', 'service'
	UserType       string    `json:"user_type"`       // 'normal' or 'service'
	Permissions    []string  `json:"permissions"`     // Unified permissions for all users
	TokenType      TokenType `json:"token_type"`      // 'access' or 'refresh'
	jwt.RegisteredClaims
}