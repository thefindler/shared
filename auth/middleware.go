// auth/middleware.go
package auth

import (
	"context"
	"strings"
	"net/http"
)

// ContextKey is a custom type for context keys to avoid collisions.
type ContextKey string

const AuthContextKey ContextKey = "authContext"

// MiddlewareService provides the authentication and authorization middleware.
type MiddlewareService struct {
	tokenService *TokenService
	db           DB // Direct DB access for org-specific secrets
}

// NewMiddlewareService creates a new middleware service.
func NewMiddlewareService(ts *TokenService, db DB) *MiddlewareService {
	return &MiddlewareService{
		tokenService: ts,
		db:           db,
	}
}

// Authenticate is the core middleware logic. It validates the token,
// checks the database, and injects the AuthContext into the request context.
func (s *MiddlewareService) Authenticate(ctx context.Context, authHeader string) (context.Context, error) {
	if authHeader == "" {
		return nil, ErrMissingToken
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, ErrInvalidToken
	}
	tokenString := parts[1]

	// 1. Parse token unverified to get OrganisationID
	unverifiedClaims, err := s.tokenService.ParseUnverified(tokenString)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// 2. Get org-specific config/secret from DB
	orgConfig, err := s.db.GetOrgConfig(ctx, unverifiedClaims.OrganisationID)
	if err != nil {
		return nil, NewAuthError("CONFIG_ERROR", "Could not load configuration for user", 500)
	}

	// 3. Validate the token with the correct secret
	claims, err := s.tokenService.ValidateToken(tokenString, []byte(orgConfig.JWTSecret))
	if err != nil {
		return nil, err // ValidateToken returns ErrInvalidToken
	}
	
	if claims.TokenType != AccessToken {
		return nil, NewAuthError("INVALID_TOKEN_TYPE", "Access token required", 401)
	}

	// 4. Perform DB validation to ensure user/service is still active
	if claims.UserType == "service" {
		if err := s.db.ValidateServiceActive(ctx, claims.UserID); err != nil {
			return nil, err
		}
	} else {
		orgIDStr := ""
		if claims.OrganisationID != nil {
			orgIDStr = *claims.OrganisationID
		}
		if err := s.db.ValidateUserActive(ctx, claims.UserID, orgIDStr); err != nil {
			return nil, err
		}
	}

	// 5. Create and inject AuthContext
	authCtx := &AuthContext{
		UserID:         claims.UserID,
		OrganisationID: claims.OrganisationID,
		Username:       claims.Username,
		Role:           claims.Role,
		UserType:       claims.UserType,
		Permissions:    claims.Permissions,
	}

	// Return a new context with the value
	return context.WithValue(ctx, AuthContextKey, authCtx), nil
}

// Middleware is a factory for creating a new HTTP middleware that enforces
// a specific authorization requirement.
func (s *MiddlewareService) Middleware(requirement *AuthRequirement) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Authentication
			authHeader := r.Header.Get("Authorization")
			ctx, err := s.Authenticate(r.Context(), authHeader)
			if err != nil {
				handleAuthError(w, err)
				return
			}

			// 2. Authorization
			if requirement != nil {
				// Role check
				if len(requirement.RequiredRoles) > 0 {
					if err := AuthorizeRole(ctx, requirement.RequiredRoles); err != nil {
						handleAuthError(w, err)
						return
					}
				}

				// Permission check
				if len(requirement.RequiredPermissions) > 0 {
					if err := AuthorizePermission(ctx, requirement.RequiredPermissions); err != nil {
						handleAuthError(w, err)
						return
					}
				}
			}

			// If all checks pass, proceed with the original handler
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// handleAuthError is a helper to write a structured auth error to the response.
func handleAuthError(w http.ResponseWriter, err error) {
	if authErr, ok := err.(*AuthError); ok {
		http.Error(w, authErr.Message, authErr.Code)
	} else {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

// --- Authorization Helpers ---

// AuthorizeRole checks if the user in the context has one of the required roles.
func AuthorizeRole(ctx context.Context, allowedRoles []string) error {
	authCtx, ok := ctx.Value(AuthContextKey).(*AuthContext)
	if !ok {
		return ErrMissingToken // Or a more specific "context missing" error
	}

	for _, role := range allowedRoles {
		if authCtx.Role == role {
			return nil
		}
	}

	return ErrInsufficientRole
}

// AuthorizePermission checks if a service user has all required permissions.
func AuthorizePermission(ctx context.Context, requiredPerms []string) error {
    authCtx, ok := ctx.Value(AuthContextKey).(*AuthContext)
	if !ok || authCtx.UserType != "service" {
		return ErrInsufficientPerms
	}

    // Create a map of the user's permissions for efficient lookup
    userPerms := make(map[string]struct{})
    for _, p := range authCtx.Permissions {
        userPerms[p] = struct{}{}
    }

    // Check if all required permissions are present
    for _, reqP := range requiredPerms {
        if _, ok := userPerms[reqP]; !ok {
            return ErrInsufficientPerms
        }
    }

	return nil
}