// auth/token.go
package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenService is responsible for generating and validating JWTs.
type TokenService struct {
	secretKey []byte
	issuer    string
}

// NewTokenService creates a new instance of the TokenService.
func NewTokenService(secretKey, issuer string) (*TokenService, error) {
	if secretKey == "" {
		return nil, fmt.Errorf("JWT secret key cannot be empty")
	}
	return &TokenService{
		secretKey: []byte(secretKey),
		issuer:    issuer,
	}, nil
}

// GenerateToken creates a new JWT with the given claims and TTL.
func (s *TokenService) GenerateToken(claims UserClaims, ttl time.Duration) (string, error) {
	now := time.Now()
	claims.RegisteredClaims = jwt.RegisteredClaims{
		ID:        uuid.NewString(),
		Issuer:    s.issuer,
		Subject:   claims.UserID,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secretKey)
}

// ValidateToken parses and validates a token string with a dynamic secret.
func (s *TokenService) ValidateToken(tokenString string, secretKey []byte) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		return nil, ErrInvalidToken // Use predefined error
	}

	if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}

// ParseUnverified parses a token without verifying its signature.
// This is useful for reading claims like OrganisationID before validation.
func (s *TokenService) ParseUnverified(tokenString string) (*UserClaims, error) {
	parser := new(jwt.Parser)
	token, _, err := parser.ParseUnverified(tokenString, &UserClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token unverified: %w", err)
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}