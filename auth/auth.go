package auth

// This file provides the main universal API for the auth package
// It re-exports key functions and provides framework-agnostic interfaces

import (
	"context"
	"fmt"
)

// Version of the auth package
const Version = "2.0.0"

// Universal Auth API - Framework Agnostic

// AuthenticateToken performs complete token validation (JWT + DB)
func AuthenticateToken(ctx context.Context, tokenString string) (*AuthContext, error) {
	return ValidateTokenWithDB(ctx, tokenString)
}

// AuthenticateRequest performs authentication for any HTTP request
type AuthRequest struct {
	AuthorizationHeader string
	Context             context.Context
}

// Authenticate validates an auth request and returns context
func Authenticate(req AuthRequest) (*AuthContext, error) {
	tokenString, err := ExtractTokenFromHeader(req.AuthorizationHeader)
	if err != nil {
		return nil, err
	}
	
	return ValidateTokenWithDB(req.Context, tokenString)
}

// Authorization helpers

// AuthorizeUser checks if user has required role
func AuthorizeUser(authCtx *AuthContext, allowedRoles []string) error {
	return ValidateRole(authCtx, allowedRoles)
}

// AuthorizeService checks if service has required permissions
func AuthorizeService(ctx context.Context, authCtx *AuthContext, requiredPermissions []string) error {
	return ValidateServicePermissions(ctx, authCtx, requiredPermissions)
}

// Package status and health checks

// IsInitialized checks if the auth package has been initialized
func IsInitialized() bool {
	return globalAuthConfig != nil
}

// HealthCheck performs a comprehensive health check
func HealthCheck(ctx context.Context) map[string]interface{} {
	status := map[string]interface{}{
		"version":     Version,
		"initialized": IsInitialized(),
	}
	
	if !IsInitialized() {
		status["error"] = "Auth package not initialized"
		return status
	}
	
	status["config"] = map[string]interface{}{
		"skip_db_validation": globalAuthConfig.SkipDBValidation,
		"cache_enabled":      globalCache != nil,
	}
	
	if globalCache != nil {
		status["cache_stats"] = GetCacheStats()
	}
	
	// Test JWT functionality
	testToken, err := CreateAccessToken("test", "test", "test", "admin")
	if err != nil {
		status["jwt_error"] = err.Error()
	} else {
		_, _, err = ValidateToken(testToken)
		if err != nil {
			status["jwt_validation_error"] = err.Error()
		} else {
			status["jwt_status"] = "healthy"
		}
	}
	
	return status
}

// Cache management

// ClearCache clears all cached validation results
func ClearCache() {
	if globalCache != nil {
		globalCache.ClearAll()
	}
}

// InvalidateUser removes user from cache for immediate revocation
func InvalidateUser(userID, orgID string) {
	InvalidateUserCache(userID, orgID)
}

// InvalidateService removes service from cache for immediate revocation
func InvalidateService(serviceName string) {
	InvalidateServiceCache(serviceName)
}

// Migration helpers for existing codebases

// MigrateFromLegacyAuth provides helpers for migrating from old auth systems
type LegacyAuthConfig struct {
	APIAuthToken string // For simple bearer token migration
	DisableAuth  bool   // For development/testing
}

// CreateMigrationConfig creates auth config for gradual migration
func CreateMigrationConfig(userValidator UserValidator, serviceValidator ServiceValidator, legacy *LegacyAuthConfig) AuthConfig {
	config := AuthConfig{
		UserValidator:    userValidator,
		ServiceValidator: serviceValidator,
		CacheConfig:      DefaultCacheConfig(),
	}
	
	// If legacy config provided, wrap validators to support old tokens
	if legacy != nil {
		if legacy.DisableAuth {
			config.SkipDBValidation = true
			config.UserValidator = &NoOpUserValidator{}
			config.ServiceValidator = &NoOpServiceValidator{}
		}
	}
	
	return config
}

// Error types for better error handling

// AuthError represents authentication/authorization errors
type AuthError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Type, e.Message)
}

// Common auth errors
var (
	ErrNotInitialized     = &AuthError{"NOT_INITIALIZED", "Auth package not initialized", 500}
	ErrMissingToken       = &AuthError{"MISSING_TOKEN", "Authorization header required", 401}
	ErrInvalidToken       = &AuthError{"INVALID_TOKEN", "Invalid or expired token", 401}
	ErrUserInactive       = &AuthError{"USER_INACTIVE", "User account inactive", 401}
	ErrServiceInactive    = &AuthError{"SERVICE_INACTIVE", "Service account inactive", 401}
	ErrInsufficientRole   = &AuthError{"INSUFFICIENT_ROLE", "Insufficient role permissions", 403}
	ErrInsufficientPerms  = &AuthError{"INSUFFICIENT_PERMISSIONS", "Insufficient service permissions", 403}
)

// Helper to create auth errors
func NewAuthError(errorType, message string, code int) *AuthError {
	return &AuthError{
		Type:    errorType,
		Message: message,
		Code:    code,
	}
}