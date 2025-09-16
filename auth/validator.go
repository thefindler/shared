package auth

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// TokenValidator handles JWT token validation with improved design
type TokenValidator struct {
	config *JWTConfig
}

// NewTokenValidator creates a new token validator
func NewTokenValidator() (*TokenValidator, error) {
	if jwtConfig == nil || len(jwtConfig.SecretKey) == 0 {
		return nil, fmt.Errorf("JWT configuration not initialized")
	}
	return &TokenValidator{config: jwtConfig}, nil
}

// ValidateToken validates a JWT token and returns appropriate claims
func ValidateToken(tokenString string) (*UserClaims, *ServiceClaims, error) {
	validator, err := NewTokenValidator()
	if err != nil {
		return nil, nil, err
	}
	return validator.validate(tokenString)
}

// ParseClaims extracts claims from token without full validation
func ParseClaims(tokenString string) (jwt.Claims, error) {
	validator, err := NewTokenValidator()
	if err != nil {
		return nil, err
	}
	
	token, err := jwt.Parse(tokenString, validator.keyFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	
	return token.Claims, nil
}

// GetTokenType extracts token type from token string
func GetTokenType(tokenString string) (TokenType, error) {
	claims, err := ParseClaims(tokenString)
	if err != nil {
		return "", err
	}
	
	mapClaims, ok := claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims format")
	}
	
	tokenType, ok := mapClaims["token_type"].(string)
	if !ok {
		return "", fmt.Errorf("missing token_type claim")
	}
	
	return TokenType(tokenType), nil
}

// validate performs full token validation and returns typed claims
func (v *TokenValidator) validate(tokenString string) (*UserClaims, *ServiceClaims, error) {
	token, err := jwt.Parse(tokenString, v.keyFunc)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid token: %w", err)
	}
	
	if !token.Valid {
		return nil, nil, fmt.Errorf("token is not valid")
	}
	
	return v.extractTypedClaims(token)
}

// keyFunc provides the key for token validation
func (v *TokenValidator) keyFunc(token *jwt.Token) (interface{}, error) {
	// Validate signing method
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return v.config.SecretKey, nil
}

// extractTypedClaims converts generic claims to specific types
func (v *TokenValidator) extractTypedClaims(token *jwt.Token) (*UserClaims, *ServiceClaims, error) {
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, fmt.Errorf("invalid claims format")
	}
	
	tokenType, ok := mapClaims["token_type"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("missing token_type claim")
	}
	
	switch TokenType(tokenType) {
	case AccessToken, RefreshToken:
		userClaims, err := v.parseUserClaims(mapClaims)
		return userClaims, nil, err
		
	case ServiceToken:
		serviceClaims, err := v.parseServiceClaims(mapClaims)
		return nil, serviceClaims, err
		
	default:
		return nil, nil, fmt.Errorf("unknown token type: %s", tokenType)
	}
}

// parseUserClaims converts map claims to UserClaims
func (v *TokenValidator) parseUserClaims(claims jwt.MapClaims) (*UserClaims, error) {
	userClaims := &UserClaims{}
	
	if userID, ok := claims["user_id"].(string); ok {
		userClaims.UserID = userID
	} else {
		return nil, fmt.Errorf("missing or invalid user_id claim")
	}
	
	if orgID, ok := claims["organisation_id"].(string); ok {
		userClaims.OrganisationID = orgID
	} else {
		return nil, fmt.Errorf("missing or invalid organisation_id claim")
	}
	
	if username, ok := claims["username"].(string); ok {
		userClaims.Username = username
	}
	
	if role, ok := claims["role"].(string); ok {
		userClaims.Role = role
	}
	
	if tokenType, ok := claims["token_type"].(string); ok {
		userClaims.TokenType = TokenType(tokenType)
	}
	
	return userClaims, nil
}

// parseServiceClaims converts map claims to ServiceClaims
func (v *TokenValidator) parseServiceClaims(claims jwt.MapClaims) (*ServiceClaims, error) {
	serviceClaims := &ServiceClaims{}
	
	if serviceName, ok := claims["service_name"].(string); ok {
		serviceClaims.ServiceName = serviceName
	} else {
		return nil, fmt.Errorf("missing or invalid service_name claim")
	}
	
	if serviceID, ok := claims["service_id"].(string); ok {
		serviceClaims.ServiceID = serviceID
	} else {
		return nil, fmt.Errorf("missing or invalid service_id claim")
	}
	
	if tokenType, ok := claims["token_type"].(string); ok {
		serviceClaims.TokenType = TokenType(tokenType)
	}
	
	if perms, ok := claims["permissions"].([]interface{}); ok {
		permissions := make([]string, len(perms))
		for i, perm := range perms {
			if permStr, ok := perm.(string); ok {
				permissions[i] = permStr
			}
		}
		serviceClaims.Permissions = permissions
	}
	
	return serviceClaims, nil
}