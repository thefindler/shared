package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"findler.com/shared/config/providers"
)

// ConfigManager manages configuration from different sources
type ConfigManager struct {
	configSource       string
	provider           providers.ConfigProvider
	fallbackProvider   providers.ConfigProvider
}

// getBootstrapConfig safely retrieves bootstrap configuration values
// This is used before the config system is fully initialized
func getBootstrapConfig(key, defaultValue string) string {
	// Try to get from environment variable first
	if value := os.Getenv(key); value != "" {
		return value
	}
	
	// Try to get from our config system if it's available
	if IsGlobalConfigInitialized() {
		if value := GetConfig(key); value != "" {
			return value
		}
	}
	
	return defaultValue
}

// NewConfigManager creates a new configuration manager
func NewConfigManager() (*ConfigManager, error) {
	// These two environment variables are needed to bootstrap the config system
	// They must be read directly since the config manager isn't available yet
	configSource := os.Getenv("CONFIG_SOURCE")
	if configSource == "" {
		configSource = "env-file" // Default to environment file
	}

	// Read provider-specific configuration only if needed
	var configSourceConfig map[string]interface{}
	if configSource != "env-file" {
		configSourceConfigStr := os.Getenv("CONFIG_SOURCE_CONFIG")
		if configSourceConfigStr != "" {
			if err := json.Unmarshal([]byte(configSourceConfigStr), &configSourceConfig); err != nil {
				return nil, fmt.Errorf("failed to parse CONFIG_SOURCE_CONFIG: %w", err)
			}
		}
	}

	// Create provider factory
	factory := &providers.ProviderFactory{}

	// Create primary provider
	providerConfig := providers.ProviderConfig{
		ProviderType: providers.ProviderType(configSource),
		Config:       configSourceConfig,
	}

	// Validate provider configuration
	if err := factory.ValidateProviderConfig(providerConfig); err != nil {
		return nil, fmt.Errorf("invalid provider configuration: %w", err)
	}

	// Create primary provider
	provider, err := factory.NewProvider(providerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create primary provider: %w", err)
	}

	// Create fallback provider (always env-file)
	fallbackConfig := providers.ProviderConfig{
		ProviderType: providers.ProviderTypeEnvFile,
		Config:       make(map[string]interface{}),
	}

	fallbackProvider, err := factory.NewProvider(fallbackConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create fallback provider: %w", err)
	}

	// Test primary provider connection
	if err := provider.TestConnection(context.Background()); err != nil {
		fmt.Printf("WARN: Primary provider connection failed, will use fallback: %v\n", err)
	}

	cm := &ConfigManager{
		configSource:     configSource,
		provider:         provider,
		fallbackProvider: fallbackProvider,
	}

	fmt.Printf("INFO: Configuration manager initialized successfully with config source: %s\n", configSource)

	return cm, nil
}

// Get retrieves a configuration value with proper key normalization
func (cm *ConfigManager) Get(key string) string {
	ctx := context.Background()
	
	// For env-file source, use the key as-is
	// For other sources (like Azure Key Vault), normalize the key
	var searchKey string
	if cm.configSource == "env-file" {
		searchKey = key
	} else {
		searchKey = cm.normalizeKey(key)
	}
	
	// Try primary provider first
	value, err := cm.provider.Get(ctx, searchKey)
	if err != nil {
		// Only try fallback if primary provider is NOT env-file
		// (because if primary is env-file, fallback is also env-file, so it will fail the same way)
		if cm.configSource != "env-file" {
			fmt.Printf("DEBUG: Primary provider failed for key %s (searched as: %s), falling back to env-file: %v\n", key, searchKey, err)
			
			// Try fallback provider with original key (env vars use underscores)
			value, err = cm.fallbackProvider.Get(ctx, key)
			if err != nil {
				fmt.Printf("DEBUG: Fallback provider also failed for key %s: %v\n", key, err)
				return ""
			}
		} else {
			// For env-file source, just return empty string without trying fallback
			return ""
		}
	}

	return value
}

// GetWithDefault retrieves a configuration value with fallback
func (cm *ConfigManager) GetWithDefault(key, defaultValue string) string {
	ctx := context.Background()
	
	// For env-file source, use the key as-is
	// For other sources (like Azure Key Vault), normalize the key
	var searchKey string
	if cm.configSource == "env-file" {
		searchKey = key
	} else {
		searchKey = cm.normalizeKey(key)
	}
	
	// Try primary provider first
	value, err := cm.provider.Get(ctx, searchKey)
	if err != nil || value == "" {
		// Only try fallback if primary provider is NOT env-file
		// (because if primary is env-file, fallback is also env-file, so it will fail the same way)
		if cm.configSource != "env-file" {
			// Try fallback provider with original key (env vars use underscores)
			value, err = cm.fallbackProvider.Get(ctx, key)
			if err != nil || value == "" {
				return defaultValue
			}
		} else {
			// For env-file source, return default value directly
			return defaultValue
		}
	}

	return value
}

// RefreshCache refreshes the configuration cache
func (cm *ConfigManager) RefreshCache() {
	// This is a generic cache refresh method
	// Specific providers can implement their own caching logic
}

// IsKeyVaultEnabled returns true if Azure Key Vault is the primary provider
func (cm *ConfigManager) IsKeyVaultEnabled() bool {
	return cm.configSource == "azure-keyvault"
}

// GetConfigSource returns the current configuration source
func (cm *ConfigManager) GetConfigSource() string {
	return cm.configSource
}

// normalizeKey normalizes keys based on the configuration source
func (cm *ConfigManager) normalizeKey(key string) string {
	switch cm.configSource {
	case "azure-keyvault":
		// Azure Key Vault doesn't support underscores, use hyphens
		return strings.ReplaceAll(key, "_", "-")
	case "gcp-secretmanager":
		// GCP Secret Manager supports underscores, no change needed
		return key
	case "aws-secretsmanager":
		// AWS Secrets Manager supports underscores, no change needed
		return key
	case "vault":
		// HashiCorp Vault supports underscores, no change needed
		return key
	default:
		// For env-file and unknown providers, no normalization needed
		return key
	}
} 