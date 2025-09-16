package auth

import (
	"github.com/golang-jwt/jwt/v5"
)

// TokenType represents the type of JWT token
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
	ServiceToken TokenType = "service"
)

// UserClaims represents claims for user tokens (access/refresh)
type UserClaims struct {
	UserID         string    `json:"user_id"`
	OrganisationID string    `json:"organisation_id"`
	Username       string    `json:"username"`
	Role           string    `json:"role"`
	TokenType      TokenType `json:"token_type"`
	jwt.RegisteredClaims
}

// ServiceClaims represents claims for service tokens
type ServiceClaims struct {
	ServiceName string      `json:"service_name"`
	ServiceID   string      `json:"service_id"`
	TokenType   TokenType   `json:"token_type"`
	Permissions []string    `json:"permissions"`
	jwt.RegisteredClaims
}