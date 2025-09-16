package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenGenerator handles JWT token creation with improved design
type TokenGenerator struct {
	config *JWTConfig
}

// NewTokenGenerator creates a new token generator
func NewTokenGenerator() (*TokenGenerator, error) {
	if jwtConfig == nil {
		return nil, fmt.Errorf("JWT configuration not initialized")
	}
	if len(jwtConfig.SecretKey) == 0 {
		return nil, fmt.Errorf("JWT secret key not configured")
	}
	return &TokenGenerator{config: jwtConfig}, nil
}

// CreateAccessToken creates a new access token for a user
func CreateAccessToken(userID, organisationID, username, role string) (string, error) {
	gen, err := NewTokenGenerator()
	if err != nil {
		return "", err
	}
	
	claims := gen.buildUserClaims(userID, organisationID, username, role, AccessToken, gen.config.AccessTokenExpiry)
	return gen.signToken(claims)
}

// CreateRefreshToken creates a new refresh token for a user  
func CreateRefreshToken(userID, organisationID, username, role string) (string, error) {
	gen, err := NewTokenGenerator()
	if err != nil {
		return "", err
	}
	
	claims := gen.buildUserClaims(userID, organisationID, username, role, RefreshToken, gen.config.RefreshTokenExpiry)
	return gen.signToken(claims)
}

// CreateServiceToken creates a new service token
func CreateServiceToken(serviceName, serviceID string, permissions []string, expiry time.Duration) (string, error) {
	gen, err := NewTokenGenerator()
	if err != nil {
		return "", err
	}
	
	claims := gen.buildServiceClaims(serviceName, serviceID, permissions, expiry)
	return gen.signToken(claims)
}

// buildUserClaims creates user claims with consistent structure
func (g *TokenGenerator) buildUserClaims(userID, orgID, username, role string, tokenType TokenType, expiry time.Duration) UserClaims {
	now := time.Now()
	return UserClaims{
		UserID:         userID,
		OrganisationID: orgID,
		Username:       username,
		Role:           role,
		TokenType:      tokenType,
		RegisteredClaims: g.buildRegisteredClaims(userID, now, expiry),
	}
}

// buildServiceClaims creates service claims with consistent structure
func (g *TokenGenerator) buildServiceClaims(serviceName, serviceID string, permissions []string, expiry time.Duration) ServiceClaims {
	now := time.Now()
	return ServiceClaims{
		ServiceName: serviceName,
		ServiceID:   serviceID,
		TokenType:   ServiceToken,
		Permissions: permissions,
		RegisteredClaims: g.buildRegisteredClaims(serviceID, now, expiry),
	}
}

// buildRegisteredClaims creates standard JWT claims
func (g *TokenGenerator) buildRegisteredClaims(subject string, now time.Time, expiry time.Duration) jwt.RegisteredClaims {
	return jwt.RegisteredClaims{
		ID:        uuid.New().String(),
		Issuer:    g.config.Issuer,
		Subject:   subject,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
	}
}

// signToken signs any claims and returns token string
func (g *TokenGenerator) signToken(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(g.config.SecretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return tokenString, nil
}