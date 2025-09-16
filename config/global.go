package config

import (
	"sync"
)

var (
	globalConfigManager *ConfigManager
	globalConfigOnce    sync.Once
	globalConfigMutex   sync.RWMutex
)

// InitGlobalConfig initializes the global configuration manager
// This should be called once at application startup
func InitGlobalConfig() error {
	var err error
	globalConfigOnce.Do(func() {
		globalConfigManager, err = NewConfigManager()
	})
	return err
}

// GetGlobalConfig returns the global configuration manager instance
// This is safe to call from any package after InitGlobalConfig has been called
func GetGlobalConfig() *ConfigManager {
	globalConfigMutex.RLock()
	defer globalConfigMutex.RUnlock()
	return globalConfigManager
}

// GetConfig is a simple method to get configuration values
// It handles all the complexity internally - just call GetConfig("KEY-NAME")
func GetConfig(key string) string {
	if !IsGlobalConfigInitialized() {
		return ""
	}
	return GetGlobalConfig().Get(key)
}

// GetConfigWithDefault is a simple method to get configuration values with fallback
func GetConfigWithDefault(key, defaultValue string) string {
	if !IsGlobalConfigInitialized() {
		return defaultValue
	}
	return GetGlobalConfig().GetWithDefault(key, defaultValue)
}

// SetGlobalConfig allows setting the global config (mainly for testing)
func SetGlobalConfig(cm *ConfigManager) {
	globalConfigMutex.Lock()
	defer globalConfigMutex.Unlock()
	globalConfigManager = cm
}

// IsGlobalConfigInitialized checks if the global config has been initialized
func IsGlobalConfigInitialized() bool {
	globalConfigMutex.RLock()
	defer globalConfigMutex.RUnlock()
	return globalConfigManager != nil
} 