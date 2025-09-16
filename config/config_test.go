package config

import (
	"os"
	"testing"
)

func TestGetConfig(t *testing.T) {
	// Test environment variable config
	testKey := "TEST_CONFIG_KEY"
	testValue := "test_config_value"
	
	// Set environment variable
	os.Setenv(testKey, testValue)
	defer os.Unsetenv(testKey)
	
	// Initialize config
	err := InitGlobalConfig()
	if err != nil {
		t.Fatalf("Failed to initialize config: %v", err)
	}
	
	// Test GetConfig
	result := GetConfig(testKey)
	if result != testValue {
		t.Errorf("GetConfig(%s) = %s; want %s", testKey, result, testValue)
	}
	
	// Test GetConfigWithDefault with existing key
	result = GetConfigWithDefault(testKey, "default_value")
	if result != testValue {
		t.Errorf("GetConfigWithDefault(%s, 'default_value') = %s; want %s", testKey, result, testValue)
	}
	
	// Test GetConfigWithDefault with non-existing key
	nonExistentKey := "NON_EXISTENT_KEY"
	defaultValue := "default_value"
	result = GetConfigWithDefault(nonExistentKey, defaultValue)
	if result != defaultValue {
		t.Errorf("GetConfigWithDefault(%s, %s) = %s; want %s", nonExistentKey, defaultValue, result, defaultValue)
	}
}

func TestIsGlobalConfigInitialized(t *testing.T) {
	// Initialize config (this is safe to call multiple times due to sync.Once)
	err := InitGlobalConfig()
	if err != nil {
		t.Fatalf("Failed to initialize config: %v", err)
	}
	
	// Should be true after initialization
	if !IsGlobalConfigInitialized() {
		t.Error("IsGlobalConfigInitialized() = false; want true")
	}
}

func TestConfigManagerCreation(t *testing.T) {
	// Test creating a config manager
	manager, err := NewConfigManager()
	if err != nil {
		t.Fatalf("NewConfigManager() failed: %v", err)
	}
	
	if manager == nil {
		t.Error("NewConfigManager() returned nil manager")
	}
	
	// Test that we can get a value
	testKey := "TEST_MANAGER_KEY"
	testValue := "test_manager_value"
	os.Setenv(testKey, testValue)
	defer os.Unsetenv(testKey)
	
	result := manager.Get(testKey)
	if result != testValue {
		t.Errorf("manager.Get(%s) = %s; want %s", testKey, result, testValue)
	}
}