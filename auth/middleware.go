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
	
	// 1. Validate JWT structure, signature, expiry (existing function)
	userClaims, serviceClaims, err := ValidateToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	
	// Skip DB validation if configured
	if globalAuthConfig.SkipDBValidation {
		return buildAuthContext(userClaims, serviceClaims), nil
	}
	
	// 2. Validate against database
	if userClaims != nil {
		// Ensure it's an access token for API calls
		if userClaims.TokenType != AccessToken {
			return nil, fmt.Errorf("access token required for API calls")
		}
		
		// Validate user is still active in DB
		err = globalAuthConfig.UserValidator.ValidateUserActive(ctx, userClaims.UserID, userClaims.OrganisationID)
		if err != nil {
			return nil, fmt.Errorf("user validation failed: %w", err)
		}
	}
	
	if serviceClaims != nil {
		// Validate service is still active in DB
		err = globalAuthConfig.ServiceValidator.ValidateServiceActive(ctx, serviceClaims.ServiceName)
		if err != nil {
			return nil, fmt.Errorf("service validation failed: %w", err)
		}
	}
	
	// Build and return auth context
	return buildAuthContext(userClaims, serviceClaims), nil
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
	
	if authCtx.Service == nil {
		return fmt.Errorf("invalid service context")
	}
	
	// Check if service has all required permissions
	for _, requiredPerm := range requiredPermissions {
		hasPermission := false
		for _, servicePerm := range authCtx.Service.Permissions {
			if servicePerm == requiredPerm {
				hasPermission = true
				break
			}
		}
		if !hasPermission {
			return fmt.Errorf("insufficient service permissions. Missing: %s", requiredPerm)
		}
	}
	
	// Additional DB validation for service permissions (if needed)
	if globalAuthConfig != nil && !globalAuthConfig.SkipDBValidation {
		err := globalAuthConfig.ServiceValidator.ValidateServicePermissions(
			ctx, authCtx.Service.ServiceName, requiredPermissions)
		if err != nil {
			return fmt.Errorf("service permission validation failed: %w", err)
		}
	}
	
	return nil
}

// buildAuthContext creates AuthContext from claims (without DB validation)
func buildAuthContext(userClaims *UserClaims, serviceClaims *ServiceClaims) *AuthContext {
	if userClaims != nil {
		return &AuthContext{
			AuthType: "user",
			User: &AuthUser{
				UserID:         userClaims.UserID,
				OrganisationID: userClaims.OrganisationID,
				Username:       userClaims.Username,
				Role:           userClaims.Role,
			},
		}
	}
	
	if serviceClaims != nil {
		return &AuthContext{
			AuthType: "service",
			Service: &AuthService{
				ServiceName: serviceClaims.ServiceName,
				ServiceID:   serviceClaims.ServiceID,
				Permissions: serviceClaims.Permissions,
			},
		}
	}
	
	return nil
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