package fiber

import (
	"strings"

	"findler.com/shared/auth"
	"github.com/gofiber/fiber/v2"
)

// Universal Fiber middleware functions

// RequireAuth validates JWT token and performs DB validation
func RequireAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Extract Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authorization header required",
			})
		}

		// Extract token from Bearer header
		tokenString, err := auth.ExtractTokenFromHeader(authHeader)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Validate token with DB
		authCtx, err := auth.ValidateTokenWithDB(c.Context(), tokenString)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid token",
			})
		}

		// Set auth context in fiber locals
		c.Locals("auth_context", authCtx)
		
		// Set individual fields for backward compatibility
		if authCtx.User != nil {
			c.Locals("auth_type", "user")
			c.Locals("user_id", authCtx.User.UserID)
			c.Locals("org_id", authCtx.User.OrganisationID)
			c.Locals("username", authCtx.User.Username)
			c.Locals("role", authCtx.User.Role)
		}
		
		if authCtx.Service != nil {
			c.Locals("auth_type", "service")
			c.Locals("service_name", authCtx.Service.ServiceName)
			c.Locals("service_id", authCtx.Service.ServiceID)
			c.Locals("permissions", authCtx.Service.Permissions)
		}

		return c.Next()
	}
}

// RequireRole validates that user has one of the specified roles
func RequireRole(allowedRoles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authCtx, ok := c.Locals("auth_context").(*auth.AuthContext)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authentication required",
			})
		}

		err := auth.ValidateRole(authCtx, allowedRoles)
		if err != nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.Next()
	}
}

// RequireServicePermission validates that service has required permissions
func RequireServicePermission(requiredPermissions ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authCtx, ok := c.Locals("auth_context").(*auth.AuthContext)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authentication required",
			})
		}

		err := auth.ValidateServicePermissions(c.Context(), authCtx, requiredPermissions)
		if err != nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		return c.Next()
	}
}

// Convenience middleware functions
func RequireAdmin() fiber.Handler {
	return RequireRole("admin")
}

func RequireAdminOrManager() fiber.Handler {
	return RequireRole("admin", "agent-manager")
}

// Context helper functions

// GetUserFromContext extracts authenticated user from context
func GetUserFromContext(c *fiber.Ctx) (*auth.AuthUser, error) {
	authCtx, ok := c.Locals("auth_context").(*auth.AuthContext)
	if !ok {
		return nil, fiber.NewError(fiber.StatusBadRequest, "No authentication context found")
	}
	
	if authCtx.AuthType != "user" || authCtx.User == nil {
		return nil, fiber.NewError(fiber.StatusBadRequest, "No user authentication found")
	}
	
	return authCtx.User, nil
}

// GetServiceFromContext extracts authenticated service from context
func GetServiceFromContext(c *fiber.Ctx) (*auth.AuthService, error) {
	authCtx, ok := c.Locals("auth_context").(*auth.AuthContext)
	if !ok {
		return nil, fiber.NewError(fiber.StatusBadRequest, "No authentication context found")
	}
	
	if authCtx.AuthType != "service" || authCtx.Service == nil {
		return nil, fiber.NewError(fiber.StatusBadRequest, "No service authentication found")
	}
	
	return authCtx.Service, nil
}

// GetAuthContext extracts the full auth context
func GetAuthContext(c *fiber.Ctx) (*auth.AuthContext, error) {
	authCtx, ok := c.Locals("auth_context").(*auth.AuthContext)
	if !ok {
		return nil, fiber.NewError(fiber.StatusBadRequest, "No authentication context found")
	}
	
	return authCtx, nil
}

// Legacy middleware for backward compatibility

// JWTMiddleware provides backward compatibility with existing API service
func JWTMiddleware() fiber.Handler {
	return RequireAuth()
}

// RequireBearer provides a simple token validation (for migration)
func RequireBearer() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "missing bearer token",
			})
		}

		// For now, just validate the JWT structure
		// This can be enhanced later to use full DB validation
		tokenString := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		_, _, err := auth.ValidateToken(tokenString)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "invalid token",
			})
		}

		c.Locals("auth_token", tokenString)
		return c.Next()
	}
}