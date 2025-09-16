package auth

import (
	"os"
	"testing"
	"time"

	"findler.com/shared/config"
)

func TestMain(m *testing.M) {
	// Setup test environment
	os.Setenv("JWT_SECRET_KEY", "test-secret-key-for-jwt-signing")
	os.Setenv("JWT_ISSUER", "test-issuer")
	os.Setenv("ACCESS_TOKEN_EXPIRY", "15m")
	os.Setenv("REFRESH_TOKEN_EXPIRY", "24h")
	
	// Initialize config and JWT
	config.InitGlobalConfig()
	InitializeJWTConfig()
	
	// Run tests
	code := m.Run()
	
	// Cleanup
	os.Unsetenv("JWT_SECRET_KEY")
	os.Unsetenv("JWT_ISSUER")
	os.Unsetenv("ACCESS_TOKEN_EXPIRY")
	os.Unsetenv("REFRESH_TOKEN_EXPIRY")
	
	os.Exit(code)
}

func TestTokenGeneration(t *testing.T) {
	// Test access token
	accessToken, err := CreateAccessToken("user123", "org456", "john.doe", "admin")
	if err != nil {
		t.Fatalf("Failed to create access token: %v", err)
	}
	if accessToken == "" {
		t.Error("Access token is empty")
	}
	
	// Test refresh token
	refreshToken, err := CreateRefreshToken("user123", "org456", "john.doe", "admin")
	if err != nil {
		t.Fatalf("Failed to create refresh token: %v", err)
	}
	if refreshToken == "" {
		t.Error("Refresh token is empty")
	}
	
	// Test service token
	serviceToken, err := CreateServiceToken("test-service", "service123", []string{"read", "write"}, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create service token: %v", err)
	}
	if serviceToken == "" {
		t.Error("Service token is empty")
	}
}

func TestTokenValidation(t *testing.T) {
	// Create tokens for testing
	accessToken, _ := CreateAccessToken("user123", "org456", "john.doe", "admin")
	serviceToken, _ := CreateServiceToken("test-service", "service123", []string{"read", "write"}, time.Hour)
	
	// Test access token validation
	userClaims, serviceClaims, err := ValidateToken(accessToken)
	if err != nil {
		t.Fatalf("Failed to validate access token: %v", err)
	}
	if userClaims == nil {
		t.Error("User claims should not be nil for access token")
	}
	if serviceClaims != nil {
		t.Error("Service claims should be nil for access token")
	}
	if userClaims.UserID != "user123" {
		t.Errorf("Expected user_id 'user123', got '%s'", userClaims.UserID)
	}
	
	// Test service token validation
	userClaims, serviceClaims, err = ValidateToken(serviceToken)
	if err != nil {
		t.Fatalf("Failed to validate service token: %v", err)
	}
	if userClaims != nil {
		t.Error("User claims should be nil for service token")
	}
	if serviceClaims == nil {
		t.Error("Service claims should not be nil for service token")
	}
	if serviceClaims.ServiceName != "test-service" {
		t.Errorf("Expected service_name 'test-service', got '%s'", serviceClaims.ServiceName)
	}
}

func TestTokenTypeExtraction(t *testing.T) {
	accessToken, _ := CreateAccessToken("user123", "org456", "john.doe", "admin")
	serviceToken, _ := CreateServiceToken("test-service", "service123", []string{"read"}, time.Hour)
	
	// Test access token type
	tokenType, err := GetTokenType(accessToken)
	if err != nil {
		t.Fatalf("Failed to get token type: %v", err)
	}
	if tokenType != AccessToken {
		t.Errorf("Expected AccessToken, got %s", tokenType)
	}
	
	// Test service token type
	tokenType, err = GetTokenType(serviceToken)
	if err != nil {
		t.Fatalf("Failed to get token type: %v", err)
	}
	if tokenType != ServiceToken {
		t.Errorf("Expected ServiceToken, got %s", tokenType)
	}
}

func TestInvalidTokens(t *testing.T) {
	// Test invalid token string
	_, _, err := ValidateToken("invalid.token.string")
	if err == nil {
		t.Error("Expected error for invalid token")
	}
	
	// Test empty token
	_, _, err = ValidateToken("")
	if err == nil {
		t.Error("Expected error for empty token")
	}
}

func BenchmarkTokenGeneration(b *testing.B) {
	b.Run("AccessToken", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := CreateAccessToken("user123", "org456", "john.doe", "admin")
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	
	b.Run("ServiceToken", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := CreateServiceToken("test-service", "service123", []string{"read", "write"}, time.Hour)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkTokenValidation(b *testing.B) {
	token, _ := CreateAccessToken("user123", "org456", "john.doe", "admin")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := ValidateToken(token)
		if err != nil {
			b.Fatal(err)
		}
	}
}