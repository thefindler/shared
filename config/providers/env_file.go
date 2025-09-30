package providers

import (
	"context"
	"fmt"
	"os"
)

// EnvFileProvider implements ConfigProvider for environment variables
type EnvFileProvider struct {
	config map[string]interface{}
}

// NewEnvFileProvider creates a new environment file provider
func NewEnvFileProvider(config ProviderConfig) (ConfigProvider, error) {
	return &EnvFileProvider{
		config: config.Config,
	}, nil
}

// Get retrieves a configuration value from environment variables
func (ep *EnvFileProvider) Get(ctx context.Context, key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("environment variable '%s' not set", key)
	}
	return value, nil
}

// GetWithDefault retrieves a configuration value with fallback
func (ep *EnvFileProvider) GetWithDefault(ctx context.Context, key, defaultValue string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue, nil
	}
	return value, nil
}
