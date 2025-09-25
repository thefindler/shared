package auth

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AuthService provides core authentication logic.
type AuthService struct {
	db           DB
	tokenService *TokenService
}

// NewAuthService creates a new authentication service.
func NewAuthService(db DB, ts *TokenService) *AuthService {
	return &AuthService{
		db:           db,
		tokenService: ts,
	}
}

// Login validates credentials and returns new access and refresh tokens.
func (s *AuthService) Login(ctx context.Context, username, password string) (string, string, error) {
	user, err := s.db.GetUserByUsername(ctx, username)
	if err != nil {
		return "", "", NewAuthError("INVALID_CREDENTIALS", "Invalid username or password", 401)
	}

	if !user.IsActive {
		return "", "", ErrUserInactive
	}

	if !VerifyPassword(password, user.PasswordHash) {
		return "", "", NewAuthError("INVALID_CREDENTIALS", "Invalid username or password", 401)
	}

	orgConfig, err := s.db.GetOrgConfig(ctx, user.OrganisationID)
	if err != nil {
		return "", "", fmt.Errorf("could not retrieve organisation config: %w", err)
	}

	// Generate access token
	accessClaims := s.createUserClaims(user, AccessToken)
	accessToken, err := s.tokenService.GenerateToken(accessClaims, orgConfig.AccessTokenTTL)
	if err != nil {
		return "", "", fmt.Errorf("could not generate access token: %w", err)
	}

	// Generate refresh token
	refreshClaims := s.createUserClaims(user, RefreshToken)
	refreshToken, err := s.tokenService.GenerateToken(refreshClaims, orgConfig.RefreshTokenTTL)
	if err != nil {
		return "", "", fmt.Errorf("could not generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// Refresh generates a new access token from a valid refresh token.
func (s *AuthService) Refresh(ctx context.Context, refreshTokenString string) (string, error) {
	// 1. Parse token unverified to get OrganisationID
	claims, err := s.tokenService.ParseUnverified(refreshTokenString)
	if err != nil {
		return "", ErrInvalidToken
	}

	// 2. Get org-specific config/secret
	orgConfig, err := s.db.GetOrgConfig(ctx, claims.OrganisationID)
	if err != nil {
		return "", fmt.Errorf("could not find organisation for token: %w", err)
	}

	// 3. Validate token with the correct secret
	validatedClaims, err := s.tokenService.ValidateToken(refreshTokenString, []byte(orgConfig.JWTSecret))
	if err != nil {
		return "", err
	}

	if validatedClaims.TokenType != RefreshToken {
		return "", NewAuthError("INVALID_TOKEN_TYPE", "Refresh token required", 401)
	}

	// 4. Check if token is denied (logged out)
	if denied, _ := s.db.IsTokenDenied(ctx, validatedClaims.ID); denied {
		return "", NewAuthError("TOKEN_REVOKED", "Token has been revoked", 401)
	}

	// 5. Get fresh user data to ensure user is still active
	user, err := s.db.GetUserByID(ctx, validatedClaims.UserID)
	if err != nil || !user.IsActive {
		return "", ErrUserInactive
	}

	// 6. Generate a new access token
	accessClaims := s.createUserClaims(user, AccessToken)
	accessToken, err := s.tokenService.GenerateToken(accessClaims, orgConfig.AccessTokenTTL)
	if err != nil {
		return "", fmt.Errorf("could not generate new access token: %w", err)
	}

	return accessToken, nil
}

// Logout revokes a refresh token by adding its JTI to a denylist.
func (s *AuthService) Logout(ctx context.Context, refreshTokenString string) error {
	claims, err := s.tokenService.ParseUnverified(refreshTokenString)
	if err != nil {
		// Don't return error for invalid tokens, just fail silently.
		return nil
	}
	// Deny token until its natural expiry time
	return s.db.DenyToken(ctx, claims.ID, claims.ExpiresAt.Time)
}

// CreateUser creates a new user account.
func (s *AuthService) CreateUser(ctx context.Context, username, password, role, userType string, orgID *string, permissions []string) error {
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("could not hash password: %w", err)
	}

	user := &User{
		ID:             uuid.NewString(),
		OrganisationID: orgID,
		Username:       username,
		PasswordHash:   hashedPassword,
		Role:           role,
		UserType:       userType,
		Permissions:    permissions,
		IsActive:       true,
	}

	return s.db.CreateUser(ctx, user)
}

// createUserClaims is a helper to create the UserClaims struct from a User object.
func (s *AuthService) createUserClaims(user *User, tokenType TokenType) UserClaims {
	return UserClaims{
		UserID:         user.ID,
		OrganisationID: user.OrganisationID,
		Username:       user.Username,
		Role:           user.Role,
		UserType:       user.UserType,
		Permissions:    user.Permissions,
		TokenType:      tokenType,
	}
}
