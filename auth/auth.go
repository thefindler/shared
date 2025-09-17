package auth

// Simple auth package entry point - no verbose wrapper functions
import (
	"fmt"
)

const Version = "2.0.0"

// IsInitialized checks if the auth package has been initialized
func IsInitialized() bool {
	return globalAuthConfig != nil
}

// ClearCache clears all cached validation results
func ClearCache() {
	if globalCache != nil {
		globalCache.ClearAll()
	}
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