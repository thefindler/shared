package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Direct token creation functions - no unnecessary structs

// CreateAccessToken creates a new access token for a user with organization-specific TTL
func CreateAccessToken(userID, organisationID, username, role, userType string, permissions []string, ttl time.Duration) (string, error) {
	if jwtConfig == nil || len(jwtConfig.SecretKey) == 0 {
		return "", fmt.Errorf("JWT configuration not initialized")
	}
	
	now := time.Now()
	var orgID *string
	if organisationID != "" {
		orgID = &organisationID
	}
	
	claims := UserClaims{
		UserID:         userID,
		OrganisationID: orgID,
		Username:       username,
		Role:           role,
		UserType:       userType,
		Permissions:    permissions,
		TokenType:      AccessToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    jwtConfig.Issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	
	return signToken(claims)
}

// CreateRefreshToken creates a new refresh token for a user with organization-specific TTL
func CreateRefreshToken(userID, organisationID, username, role, userType string, permissions []string, ttl time.Duration) (string, error) {
	if jwtConfig == nil || len(jwtConfig.SecretKey) == 0 {
		return "", fmt.Errorf("JWT configuration not initialized")
	}
	
	now := time.Now()
	var orgID *string
	if organisationID != "" {
		orgID = &organisationID
	}
	
	claims := UserClaims{
		UserID:         userID,
		OrganisationID: orgID,
		Username:       username,
		Role:           role,
		UserType:       userType,
		Permissions:    permissions,
		TokenType:      RefreshToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    jwtConfig.Issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	
	return signToken(claims)
}

// CreateServiceToken creates a new service token (now uses unified UserClaims)
// Services are treated as users with user_type="service" and role="service"
// Returns a REFRESH token since services need long-lived tokens that can be refreshed
func CreateServiceToken(serviceName, serviceID string, permissions []string, expiry time.Duration) (string, error) {
	// Services get refresh tokens for long-lived access
	return CreateRefreshToken(serviceID, "", serviceName, "service", "service", permissions, expiry)
}

// signToken signs any claims and returns token string
func signToken(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtConfig.SecretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return tokenString, nil
}