package providers

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// AzureKeyVaultProvider implements ConfigProvider for Azure Key Vault
type AzureKeyVaultProvider struct {
	client        *azsecrets.Client
	vaultURL      string
	config        map[string]interface{}
	cache         map[string]string
	cacheMutex    sync.RWMutex
	cacheExpiry   time.Time
	cacheDuration time.Duration
}

// transformKeyForAzureKeyVault converts environment variable style keys to Azure Key Vault compatible keys
// Environment: AZURE_SPEECH_KEY_CENTRAL_INDIA -> Azure Key Vault: AZURE-SPEECH-KEY-CENTRAL-INDIA
func transformKeyForAzureKeyVault(key string) string {
	return strings.ReplaceAll(key, "_", "-")
}

// transformKeyFromAzureKeyVault converts Azure Key Vault keys back to environment variable style
// Azure Key Vault: AZURE-SPEECH-KEY-CENTRAL-INDIA -> Environment: AZURE_SPEECH_KEY_CENTRAL_INDIA
func transformKeyFromAzureKeyVault(key string) string {
	return strings.ReplaceAll(key, "-", "_")
}

// NewAzureKeyVaultProvider creates a new Azure Key Vault provider
func NewAzureKeyVaultProvider(config ProviderConfig) (ConfigProvider, error) {
	// Extract vault URL from config
	vaultURL, ok := config.Config["vault_url"].(string)
	if !ok || vaultURL == "" {
		return nil, fmt.Errorf("vault_url is required in config for Azure Key Vault provider")
	}

	// Use Managed Identity for authentication
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	// Create Key Vault client
	client, err := azsecrets.NewClient(vaultURL, credential, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Key Vault client: %w", err)
	}

	provider := &AzureKeyVaultProvider{
		client:        client,
		vaultURL:      vaultURL,
		config:        config.Config,
		cache:         make(map[string]string),
		cacheDuration: 5 * time.Minute, // Cache secrets for 5 minutes
	}

	fmt.Printf("INFO: Azure Key Vault provider initialized successfully with vault URL: %s\n", vaultURL)

	return provider, nil
}

// Get retrieves a configuration value from Azure Key Vault
func (akp *AzureKeyVaultProvider) Get(ctx context.Context, key string) (string, error) {
	// Transform the key for Azure Key Vault (convert underscores to hyphens)
	azureKey := transformKeyForAzureKeyVault(key)
	
	// Check cache first using the original key
	akp.cacheMutex.RLock()
	if value, exists := akp.cache[key]; exists && time.Now().Before(akp.cacheExpiry) {
		akp.cacheMutex.RUnlock()
		return value, nil
	}
	akp.cacheMutex.RUnlock()

	// Cache miss or expired, fetch from Key Vault
	akp.cacheMutex.Lock()
	defer akp.cacheMutex.Unlock()

	// Double-check cache after acquiring write lock
	if value, exists := akp.cache[key]; exists && time.Now().Before(akp.cacheExpiry) {
		return value, nil
	}

	// Fetch from Key Vault using the transformed key
	secret, err := akp.getSecretFromKeyVault(ctx, azureKey)
	if err != nil {
		fmt.Printf("ERROR: Failed to retrieve secret from Key Vault for key %s (transformed to %s): %v\n", key, azureKey, err)
		return "", err
	}

	// Update cache with the original key
	akp.cache[key] = secret
	akp.cacheExpiry = time.Now().Add(akp.cacheDuration)

	return secret, nil
}

// GetWithDefault retrieves a configuration value with fallback
func (akp *AzureKeyVaultProvider) GetWithDefault(ctx context.Context, key, defaultValue string) (string, error) {
	value, err := akp.Get(ctx, key)
	if err != nil {
		return defaultValue, nil
	}
	return value, nil
}


// Close cleans up resources
func (akp *AzureKeyVaultProvider) Close() error {
	// The azsecrets.Client doesn't have a Close method
	// Just clean up the credential if needed in the future
	return nil
}

// getSecretFromKeyVault retrieves a secret from Azure Key Vault
func (akp *AzureKeyVaultProvider) getSecretFromKeyVault(ctx context.Context, secretName string) (string, error) {
	// Add timeout to context
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Get secret from Key Vault
	resp, err := akp.client.GetSecret(ctx, secretName, "", nil)
	if err != nil {
		return "", fmt.Errorf("failed to get secret '%s': %w", secretName, err)
	}

	if resp.Value == nil {
		return "", fmt.Errorf("secret '%s' has no value", secretName)
	}

	fmt.Printf("INFO: Successfully retrieved secret from Key Vault for secret name: %s\n", secretName)

	return *resp.Value, nil
}
