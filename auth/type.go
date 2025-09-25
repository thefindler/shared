package auth

import (
	"github.com/golang-jwt/jwt/v5"
)

type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

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

// AuthRequirement specifies what authorization is needed for an endpoint.
// An empty struct means any authenticated user is allowed.
type AuthRequirement struct {
	RequiredRoles       []string
	RequiredPermissions []string
}
