package auth

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Direct token validation functions - no unnecessary structs

// ValidateToken validates a JWT token and returns appropriate claims
func ValidateToken(tokenString string) (*UserClaims, *ServiceClaims, error) {
	if jwtConfig == nil || len(jwtConfig.SecretKey) == 0 {
		return nil, nil, fmt.Errorf("JWT configuration not initialized")
	}
	
	token, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid token: %w", err)
	}
	
	if !token.Valid {
		return nil, nil, fmt.Errorf("token is not valid")
	}
	
	return extractTypedClaims(token)
}

// keyFunc provides the key for token validation
func keyFunc(token *jwt.Token) (interface{}, error) {
	// Validate signing method
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return jwtConfig.SecretKey, nil
}

// extractTypedClaims converts generic claims to specific types
func extractTypedClaims(token *jwt.Token) (*UserClaims, *ServiceClaims, error) {
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
		userClaims, err := parseUserClaims(mapClaims)
		return userClaims, nil, err
		
	case ServiceToken:
		serviceClaims, err := parseServiceClaims(mapClaims)
		return nil, serviceClaims, err
		
	default:
		return nil, nil, fmt.Errorf("unknown token type: %s", tokenType)
	}
}

// parseUserClaims converts map claims to UserClaims
func parseUserClaims(claims jwt.MapClaims) (*UserClaims, error) {
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
func parseServiceClaims(claims jwt.MapClaims) (*ServiceClaims, error) {
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