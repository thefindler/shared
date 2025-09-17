package auth

import (
	"context"
	"fmt"
	"strings"
)

// Global auth configuration
var (
	globalAuthConfig *AuthConfig
	globalCache      *ValidationCache
)

// Initialize sets up the global auth configuration
func Initialize(config AuthConfig) error {
	if config.UserValidator == nil {
		return fmt.Errorf("UserValidator is required")
	}
	if config.ServiceValidator == nil {
		return fmt.Errorf("ServiceValidator is required")
	}
	
	// Set up caching if not disabled
	if config.CacheConfig == nil {
		config.CacheConfig = DefaultCacheConfig()
	}
	
	// Create cache
	globalCache = NewValidationCache(config.CacheConfig)
	
	// Wrap validators with caching if not disabled
	if !config.SkipDBValidation {
		config.UserValidator = NewCachedUserValidator(config.UserValidator, globalCache)
		config.ServiceValidator = NewCachedServiceValidator(config.ServiceValidator, globalCache)
	}
	
	globalAuthConfig = &config
	return nil
}

// GetAuthConfig returns the global auth configuration
func GetAuthConfig() *AuthConfig {
	return globalAuthConfig
}

// GetCache returns the global validation cache
func GetCache() *ValidationCache {
	return globalCache
}

// ValidateTokenWithDB performs JWT validation + DB validation
func ValidateTokenWithDB(ctx context.Context, tokenString string) (*AuthContext, error) {
	if globalAuthConfig == nil {
		return nil, fmt.Errorf("auth package not initialized - call auth.Initialize() first")
	}
	
	// 1. Validate JWT structure, signature, expiry (unified function)
	claims, err := ValidateToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	
	// Skip DB validation if configured
	if globalAuthConfig.SkipDBValidation {
		return buildAuthContext(claims), nil
	}
	
	// 2. Ensure it's an access token for API calls
	if claims.TokenType != AccessToken {
		return nil, fmt.Errorf("access token required for API calls")
	}
	
	// 3. Validate against database based on user type
	if claims.UserType == "service" {
		// Validate service is still active in DB
		err = globalAuthConfig.ServiceValidator.ValidateServiceActive(ctx, claims.UserID)
		if err != nil {
			return nil, fmt.Errorf("service validation failed: %w", err)
		}
	} else {
		// Validate user is still active in DB
		var orgID string
		if claims.OrganisationID != nil {
			orgID = *claims.OrganisationID
		}
		err = globalAuthConfig.UserValidator.ValidateUserActive(ctx, claims.UserID, orgID)
		if err != nil {
			return nil, fmt.Errorf("user validation failed: %w", err)
		}
	}
	
	// Build and return auth context
	return buildAuthContext(claims), nil
}

// ExtractTokenFromHeader extracts Bearer token from Authorization header
func ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", fmt.Errorf("authorization header required")
	}
	
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("invalid authorization format. Expected: Bearer <token>")
	}
	
	return parts[1], nil
}

// ValidateRole checks if user has required role
func ValidateRole(authCtx *AuthContext, allowedRoles []string) error {
	if authCtx.AuthType != "user" {
		return fmt.Errorf("user authentication required for role validation")
	}
	
	if authCtx.User == nil {
		return fmt.Errorf("invalid user context")
	}
	
	for _, allowedRole := range allowedRoles {
		if authCtx.User.Role == allowedRole {
			return nil // Role found
		}
	}
	
	return fmt.Errorf("insufficient permissions. Required roles: %v, user role: %s", 
		allowedRoles, authCtx.User.Role)
}

// ValidateServicePermissions checks if service has required permissions
func ValidateServicePermissions(ctx context.Context, authCtx *AuthContext, requiredPermissions []string) error {
	if authCtx.AuthType != "service" {
		return fmt.Errorf("service authentication required for permission validation")
	}
	
	if authCtx.User == nil {
		return fmt.Errorf("invalid authentication context")
	}
	
	// Check if user/service has all required permissions
	for _, requiredPerm := range requiredPermissions {
		hasPermission := false
		for _, userPerm := range authCtx.User.Permissions {
			if userPerm == requiredPerm {
				hasPermission = true
				break
			}
		}
		if !hasPermission {
			return fmt.Errorf("insufficient permissions. Missing: %s", requiredPerm)
		}
	}
	
	// Additional DB validation for service permissions (if needed)
	if globalAuthConfig != nil && !globalAuthConfig.SkipDBValidation {
		err := globalAuthConfig.ServiceValidator.ValidateServicePermissions(
			ctx, authCtx.User.UserID, requiredPermissions)
		if err != nil {
			return fmt.Errorf("service permission validation failed: %w", err)
		}
	}
	
	return nil
}

// buildAuthContext creates AuthContext from claims (unified for users and services)
func buildAuthContext(claims *UserClaims) *AuthContext {
	if claims == nil {
		return nil
	}
	
	// Determine auth type for backward compatibility
	authType := "user"
	if claims.UserType == "service" {
		authType = "service"
	}
	
	return &AuthContext{
		AuthType: authType,
		User: &AuthUser{
			UserID:         claims.UserID,
			OrganisationID: claims.OrganisationID,
			Username:       claims.Username,
			Role:           claims.Role,
			UserType:       claims.UserType,
			Permissions:    claims.Permissions,
		},
	}
}

// Convenience functions for common roles
func RequireAdmin(authCtx *AuthContext) error {
	return ValidateRole(authCtx, []string{"admin"})
}

func RequireAdminOrManager(authCtx *AuthContext) error {
	return ValidateRole(authCtx, []string{"admin", "agent-manager"})
}

// InvalidateUserCache removes user from cache (for immediate revocation)
func InvalidateUserCache(userID, orgID string) {
	if globalCache != nil {
		globalCache.InvalidateUser(userID, orgID)
	}
}

// InvalidateServiceCache removes service from cache (for immediate revocation)
func InvalidateServiceCache(serviceName string) {
	if globalCache != nil {
		globalCache.InvalidateService(serviceName)
	}
}

// GetCacheStats returns cache statistics
func GetCacheStats() map[string]interface{} {
	if globalCache != nil {
		return globalCache.GetStats()
	}
	return map[string]interface{}{"cache": "disabled"}
}