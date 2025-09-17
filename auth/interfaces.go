package auth

import (
	"context"
)

// UserValidator interface for validating users against database
type UserValidator interface {
	// ValidateUserActive checks if user exists and is active
	ValidateUserActive(ctx context.Context, userID, orgID string) error
	
	// GetUserPermissions returns user's permissions (for future use)
	GetUserPermissions(ctx context.Context, userID string) ([]string, error)
}

// ServiceValidator interface for validating services against database  
type ServiceValidator interface {
	// ValidateServiceActive checks if service exists and is active
	ValidateServiceActive(ctx context.Context, serviceName string) error
	
	// ValidateServicePermissions checks if service has required permissions
	ValidateServicePermissions(ctx context.Context, serviceName string, permissions []string) error
}

// AuthConfig holds configuration for the auth middleware
type AuthConfig struct {
	UserValidator    UserValidator
	ServiceValidator ServiceValidator
	CacheConfig      *CacheConfig
	SkipDBValidation bool // For testing or special cases
}

// CacheConfig defines caching behavior for DB validation
type CacheConfig struct {
	UserStatusTTL    int // TTL in seconds for user status cache
	ServiceStatusTTL int // TTL in seconds for service status cache  
	MaxCacheSize     int // Maximum number of cache entries
}

// DefaultCacheConfig returns sensible cache defaults
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		UserStatusTTL:    30,    // 30 seconds
		ServiceStatusTTL: 300,   // 5 minutes (services change less frequently)
		MaxCacheSize:     10000, // 10k entries
	}
}

// AuthUser represents authenticated user information
type AuthUser struct {
	UserID         string `json:"user_id"`
	OrganisationID string `json:"organisation_id"`
	Username       string `json:"username"`
	Role           string `json:"role"`
}

// AuthService represents authenticated service information
type AuthService struct {
	ServiceName string   `json:"service_name"`
	ServiceID   string   `json:"service_id"`
	Permissions []string `json:"permissions"`
}

// AuthContext represents the authentication context
type AuthContext struct {
	AuthType string       `json:"auth_type"` // "user" or "service"
	User     *AuthUser    `json:"user,omitempty"`
	Service  *AuthService `json:"service,omitempty"`
}

// NoOpUserValidator provides a no-op implementation for testing
type NoOpUserValidator struct{}

func (v *NoOpUserValidator) ValidateUserActive(ctx context.Context, userID, orgID string) error {
	return nil // Always allow
}

func (v *NoOpUserValidator) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	return []string{}, nil // No permissions
}

// NoOpServiceValidator provides a no-op implementation for testing
type NoOpServiceValidator struct{}

func (v *NoOpServiceValidator) ValidateServiceActive(ctx context.Context, serviceName string) error {
	return nil // Always allow
}

func (v *NoOpServiceValidator) ValidateServicePermissions(ctx context.Context, serviceName string, permissions []string) error {
	return nil // Always allow
}

// Note: Generic database validators have been moved to specific database implementation files
// (e.g., postgres_validators.go) to avoid interface complexity and provide direct database access.