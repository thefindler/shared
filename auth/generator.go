package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Direct token creation functions - no unnecessary structs

// CreateAccessToken creates a new access token for a user
func CreateAccessToken(userID, organisationID, username, role string) (string, error) {
	if jwtConfig == nil || len(jwtConfig.SecretKey) == 0 {
		return "", fmt.Errorf("JWT configuration not initialized")
	}
	
	now := time.Now()
	claims := UserClaims{
		UserID:         userID,
		OrganisationID: organisationID,
		Username:       username,
		Role:           role,
		TokenType:      AccessToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    jwtConfig.Issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(jwtConfig.AccessTokenExpiry)),
		},
	}
	
	return signToken(claims)
}

// CreateRefreshToken creates a new refresh token for a user  
func CreateRefreshToken(userID, organisationID, username, role string) (string, error) {
	if jwtConfig == nil || len(jwtConfig.SecretKey) == 0 {
		return "", fmt.Errorf("JWT configuration not initialized")
	}
	
	now := time.Now()
	claims := UserClaims{
		UserID:         userID,
		OrganisationID: organisationID,
		Username:       username,
		Role:           role,
		TokenType:      RefreshToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    jwtConfig.Issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(jwtConfig.RefreshTokenExpiry)),
		},
	}
	
	return signToken(claims)
}

// CreateServiceToken creates a new service token
func CreateServiceToken(serviceName, serviceID string, permissions []string, expiry time.Duration) (string, error) {
	if jwtConfig == nil || len(jwtConfig.SecretKey) == 0 {
		return "", fmt.Errorf("JWT configuration not initialized")
	}
	
	now := time.Now()
	claims := ServiceClaims{
		ServiceName: serviceName,
		ServiceID:   serviceID,
		TokenType:   ServiceToken,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Issuer:    jwtConfig.Issuer,
			Subject:   serviceID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
		},
	}
	
	return signToken(claims)
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