package auth

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Direct token validation functions - no unnecessary structs

// ValidateToken validates a JWT token and returns UserClaims (unified for all users/services)
func ValidateToken(tokenString string) (*UserClaims, error) {
	if jwtConfig == nil || len(jwtConfig.SecretKey) == 0 {
		return nil, fmt.Errorf("JWT configuration not initialized")
	}
	
	token, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}
	
	return extractUserClaims(token)
}

// keyFunc provides the key for token validation
func keyFunc(token *jwt.Token) (interface{}, error) {
	// Validate signing method
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return jwtConfig.SecretKey, nil
}

// extractUserClaims converts generic claims to UserClaims (unified for all users/services)
func extractUserClaims(token *jwt.Token) (*UserClaims, error) {
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims format")
	}
	
	tokenType, ok := mapClaims["token_type"].(string)
	if !ok {
		return nil, fmt.Errorf("missing token_type claim")
	}
	
	// Only accept access and refresh tokens now
	if TokenType(tokenType) != AccessToken && TokenType(tokenType) != RefreshToken {
		return nil, fmt.Errorf("unsupported token type: %s", tokenType)
	}
	
	return parseUserClaims(mapClaims)
}

// parseUserClaims converts map claims to UserClaims
func parseUserClaims(claims jwt.MapClaims) (*UserClaims, error) {
	userClaims := &UserClaims{}
	
	if userID, ok := claims["user_id"].(string); ok {
		userClaims.UserID = userID
	} else {
		return nil, fmt.Errorf("missing or invalid user_id claim")
	}
	
	// OrganisationID can be null for global services
	if orgID, ok := claims["organisation_id"].(string); ok && orgID != "" {
		userClaims.OrganisationID = &orgID
	}
	
	if username, ok := claims["username"].(string); ok {
		userClaims.Username = username
	}
	
	if role, ok := claims["role"].(string); ok {
		userClaims.Role = role
	} else {
		return nil, fmt.Errorf("missing or invalid role claim")
	}
	
	if userType, ok := claims["user_type"].(string); ok {
		userClaims.UserType = userType
	} else {
		return nil, fmt.Errorf("missing or invalid user_type claim")
	}
	
	// Parse permissions array (handle null/nil case)
	if permsInterface, ok := claims["permissions"]; ok && permsInterface != nil {
		if permsSlice, ok := permsInterface.([]interface{}); ok {
			permissions := make([]string, len(permsSlice))
			for i, perm := range permsSlice {
				if permStr, ok := perm.(string); ok {
					permissions[i] = permStr
				} else {
					return nil, fmt.Errorf("invalid permission format at index %d", i)
				}
			}
			userClaims.Permissions = permissions
		} else {
			return nil, fmt.Errorf("permissions claim is not an array, got type: %T", permsInterface)
		}
	} else {
		// Handle null/missing permissions - default to empty array
		userClaims.Permissions = []string{}
	}
	
	if tokenType, ok := claims["token_type"].(string); ok {
		userClaims.TokenType = TokenType(tokenType)
	} else {
		return nil, fmt.Errorf("missing or invalid token_type claim")
	}
	
	return userClaims, nil
}
