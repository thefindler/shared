package auth

import (
	"fmt"
	"time"

	"findler.com/shared/config"
)

// JWTConfig holds JWT configuration
type JWTConfig struct {
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	Issuer             string
	SecretKey          []byte // HMAC secret key for HS256
}

var jwtConfig *JWTConfig

// InitializeJWTConfig initializes JWT configuration from the config system
func InitializeJWTConfig() error {
	accessTokenExpiry, err := parseDuration(config.GetConfigWithDefault("ACCESS_TOKEN_EXPIRY", "4h"), 4*time.Hour)
	if err != nil {
		return fmt.Errorf("invalid ACCESS_TOKEN_EXPIRY: %w", err)
	}

	refreshTokenExpiry, err := parseDuration(config.GetConfigWithDefault("REFRESH_TOKEN_EXPIRY", "8760h"), 8760*time.Hour)
	if err != nil {
		return fmt.Errorf("invalid REFRESH_TOKEN_EXPIRY: %w", err)
	}

	secretKey := config.GetConfig("JWT_SECRET_KEY")
	if secretKey == "" {
		return fmt.Errorf("JWT_SECRET_KEY configuration is required")
	}

	jwtConfig = &JWTConfig{
		AccessTokenExpiry:  accessTokenExpiry,
		RefreshTokenExpiry: refreshTokenExpiry,
		Issuer:             config.GetConfigWithDefault("JWT_ISSUER", "findler-api-service"),
		SecretKey:          []byte(secretKey),
	}

	return nil
}

// GetJWTConfig returns the current JWT configuration
func GetJWTConfig() *JWTConfig {
	return jwtConfig
}

// parseDuration parses duration string with fallback
func parseDuration(durationStr string, fallback time.Duration) (time.Duration, error) {
	if durationStr == "" {
		return fallback, nil
	}
	return time.ParseDuration(durationStr)
}