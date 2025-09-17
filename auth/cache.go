package auth

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CacheEntry represents a cached validation result
type CacheEntry struct {
	Value     bool      `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IsExpired checks if the cache entry has expired
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// ValidationCache provides in-memory caching for DB validation results
type ValidationCache struct {
	userCache    map[string]*CacheEntry
	serviceCache map[string]*CacheEntry
	mu           sync.RWMutex
	config       *CacheConfig
}

// NewValidationCache creates a new validation cache
func NewValidationCache(config *CacheConfig) *ValidationCache {
	if config == nil {
		config = DefaultCacheConfig()
	}
	
	cache := &ValidationCache{
		userCache:    make(map[string]*CacheEntry),
		serviceCache: make(map[string]*CacheEntry),
		config:       config,
	}
	
	// Start cleanup goroutine
	go cache.startCleanup()
	
	return cache
}

// GetUserStatus retrieves cached user validation status
func (c *ValidationCache) GetUserStatus(userID, orgID string) (bool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	key := fmt.Sprintf("%s:%s", userID, orgID)
	entry, exists := c.userCache[key]
	
	if !exists || entry.IsExpired() {
		return false, false // not found or expired
	}
	
	return entry.Value, true // value, found
}

// SetUserStatus caches user validation status
func (c *ValidationCache) SetUserStatus(userID, orgID string, isActive bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Cleanup if cache is too large
	if len(c.userCache) >= c.config.MaxCacheSize {
		c.cleanupExpiredUsers()
	}
	
	key := fmt.Sprintf("%s:%s", userID, orgID)
	c.userCache[key] = &CacheEntry{
		Value:     isActive,
		ExpiresAt: time.Now().Add(time.Duration(c.config.UserStatusTTL) * time.Second),
	}
}

// GetServiceStatus retrieves cached service validation status
func (c *ValidationCache) GetServiceStatus(serviceName string) (bool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	entry, exists := c.serviceCache[serviceName]
	
	if !exists || entry.IsExpired() {
		return false, false // not found or expired
	}
	
	return entry.Value, true // value, found
}

// SetServiceStatus caches service validation status
func (c *ValidationCache) SetServiceStatus(serviceName string, isActive bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Cleanup if cache is too large
	if len(c.serviceCache) >= c.config.MaxCacheSize {
		c.cleanupExpiredServices()
	}
	
	c.serviceCache[serviceName] = &CacheEntry{
		Value:     isActive,
		ExpiresAt: time.Now().Add(time.Duration(c.config.ServiceStatusTTL) * time.Second),
	}
}

// InvalidateUser removes user from cache (for immediate revocation)
func (c *ValidationCache) InvalidateUser(userID, orgID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	key := fmt.Sprintf("%s:%s", userID, orgID)
	delete(c.userCache, key)
}

// InvalidateService removes service from cache (for immediate revocation)
func (c *ValidationCache) InvalidateService(serviceName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	delete(c.serviceCache, serviceName)
}

// ClearAll clears all cache entries
func (c *ValidationCache) ClearAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.userCache = make(map[string]*CacheEntry)
	c.serviceCache = make(map[string]*CacheEntry)
}

// GetStats returns cache statistics
func (c *ValidationCache) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	return map[string]interface{}{
		"user_cache_size":    len(c.userCache),
		"service_cache_size": len(c.serviceCache),
		"user_ttl_seconds":   c.config.UserStatusTTL,
		"service_ttl_seconds": c.config.ServiceStatusTTL,
		"max_cache_size":     c.config.MaxCacheSize,
	}
}

// cleanupExpiredUsers removes expired user entries (called with lock held)
func (c *ValidationCache) cleanupExpiredUsers() {
	now := time.Now()
	for key, entry := range c.userCache {
		if now.After(entry.ExpiresAt) {
			delete(c.userCache, key)
		}
	}
}

// cleanupExpiredServices removes expired service entries (called with lock held)
func (c *ValidationCache) cleanupExpiredServices() {
	now := time.Now()
	for key, entry := range c.serviceCache {
		if now.After(entry.ExpiresAt) {
			delete(c.serviceCache, key)
		}
	}
}

// startCleanup runs periodic cleanup in background
func (c *ValidationCache) startCleanup() {
	ticker := time.NewTicker(5 * time.Minute) // Cleanup every 5 minutes
	defer ticker.Stop()
	
	for range ticker.C {
		c.mu.Lock()
		c.cleanupExpiredUsers()
		c.cleanupExpiredServices()
		c.mu.Unlock()
	}
}

// CachedUserValidator wraps a UserValidator with caching
type CachedUserValidator struct {
	validator UserValidator
	cache     *ValidationCache
}

// NewCachedUserValidator creates a cached user validator
func NewCachedUserValidator(validator UserValidator, cache *ValidationCache) *CachedUserValidator {
	return &CachedUserValidator{
		validator: validator,
		cache:     cache,
	}
}

// ValidateUserActive validates with caching
func (v *CachedUserValidator) ValidateUserActive(ctx context.Context, userID, orgID string) error {
	// Check cache first
	if isActive, found := v.cache.GetUserStatus(userID, orgID); found {
		if !isActive {
			return fmt.Errorf("user account inactive")
		}
		return nil
	}
	
	// Cache miss - validate against DB
	err := v.validator.ValidateUserActive(ctx, userID, orgID)
	
	// Cache the result
	v.cache.SetUserStatus(userID, orgID, err == nil)
	
	return err
}

// GetUserPermissions delegates to underlying validator (no caching for permissions)
func (v *CachedUserValidator) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	return v.validator.GetUserPermissions(ctx, userID)
}

// CachedServiceValidator wraps a ServiceValidator with caching
type CachedServiceValidator struct {
	validator ServiceValidator
	cache     *ValidationCache
}

// NewCachedServiceValidator creates a cached service validator
func NewCachedServiceValidator(validator ServiceValidator, cache *ValidationCache) *CachedServiceValidator {
	return &CachedServiceValidator{
		validator: validator,
		cache:     cache,
	}
}

// ValidateServiceActive validates with caching
func (v *CachedServiceValidator) ValidateServiceActive(ctx context.Context, serviceName string) error {
	// Check cache first
	if isActive, found := v.cache.GetServiceStatus(serviceName); found {
		if !isActive {
			return fmt.Errorf("service account inactive")
		}
		return nil
	}
	
	// Cache miss - validate against DB
	err := v.validator.ValidateServiceActive(ctx, serviceName)
	
	// Cache the result
	v.cache.SetServiceStatus(serviceName, err == nil)
	
	return err
}

// ValidateServicePermissions delegates to underlying validator (no caching for permissions)
func (v *CachedServiceValidator) ValidateServicePermissions(ctx context.Context, serviceName string, permissions []string) error {
	return v.validator.ValidateServicePermissions(ctx, serviceName, permissions)
}