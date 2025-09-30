package providers

import (
	"context"
	"fmt"
)

// ProviderType represents the type of configuration provider
type ProviderType string

const (
	ProviderTypeAzureKeyVault ProviderType = "azure-keyvault"
	ProviderTypeEnvFile       ProviderType = "env-file"
	// Future providers can be added here:
	// ProviderTypeGCPSecretManager ProviderType = "gcp-secretmanager"
	// ProviderTypeAWSSecretsManager ProviderType = "aws-secretsmanager"
)

// ConfigProvider defines the interface for any configuration source
type ConfigProvider interface {
	// Get retrieves a configuration value by key
	Get(ctx context.Context, key string) (string, error)
	
	// GetWithDefault retrieves a configuration value with fallback to default
	GetWithDefault(ctx context.Context, key, defaultValue string) (string, error)
	
}

// ProviderConfig holds configuration for a specific provider
type ProviderConfig struct {
	ProviderType ProviderType              `json:"provider_type"`
	Config       map[string]interface{}   `json:"config"`
}

// ProviderFactory creates and manages configuration providers
type ProviderFactory struct{}

// NewProvider creates a new configuration provider based on the configuration
func (pf *ProviderFactory) NewProvider(config ProviderConfig) (ConfigProvider, error) {
	switch config.ProviderType {
	case ProviderTypeAzureKeyVault:
		return NewAzureKeyVaultProvider(config)
	case ProviderTypeEnvFile:
		return NewEnvFileProvider(config)
	// Future providers can be added here:
	// case ProviderTypeGCPSecretManager:
	//     return NewGCPSecretManagerProvider(config)
	// case ProviderTypeAWSSecretsManager:
	//     return NewAWSSecretsManagerProvider(config)
	// case ProviderTypeVault:
	//     return NewVaultProvider(config)
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", config.ProviderType)
	}
}

// ValidateProviderConfig validates the configuration for a specific provider
func (pf *ProviderFactory) ValidateProviderConfig(config ProviderConfig) error {
	switch config.ProviderType {
	case ProviderTypeAzureKeyVault:
		return validateAzureKeyVaultConfig(config)
	case ProviderTypeEnvFile:
		return validateEnvFileConfig(config)
	// Future providers can be added here:
	// case ProviderTypeGCPSecretManager:
	//     return validateGCPSecretManagerConfig(config)
	// case ProviderTypeAWSSecretsManager:
	//     return validateAWSSecretsManagerConfig(config)
	// case ProviderTypeVault:
	//     return validateVaultConfig(config)
	default:
		return fmt.Errorf("unsupported provider type: %s", config.ProviderType)
	}
} 