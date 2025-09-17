package auth

import (
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SetupAuthRoutes sets up all authentication routes for a Fiber app
// This replaces the need for service-specific auth handlers
func SetupAuthRoutes(app *fiber.App, db *pgxpool.Pool) {
	// Create auth handlers
	handlers := NewAuthHandlers(db)

	// Public auth routes (no authentication required)
	authPublic := app.Group("/auth")
	authPublic.Post("/login", handlers.Login)
	authPublic.Post("/refresh", handlers.RefreshToken)
	authPublic.Post("/logout", handlers.Logout)

	// Protected auth routes (authentication required)
	authProtected := app.Group("/auth")
	authProtected.Use(requireAuthMiddleware()) // Use local middleware

	// User management routes (admin only)
	authProtected.Post("/users",
		requireRoleMiddleware("admin"),
		requireOrgIsolationMiddleware(),
		handlers.CreateNormalUser,
	)

	// Service token management (admin only)
	authProtected.Post("/service/user",
		requireRoleMiddleware("admin"),
		handlers.CreateServiceUser,
	)
	authProtected.Get("/service/permissions",
		requireRoleMiddleware("admin", "agent-manager"),
		handlers.GetAvailablePermissions,
	)
}

// Local middleware functions (to avoid circular imports)

func requireAuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Extract Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Authorization header required"})
		}

		// Extract token from Bearer header
		tokenString, err := ExtractTokenFromHeader(authHeader)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
		}

		// Validate token with DB
		authCtx, err := ValidateTokenWithDB(c.Context(), tokenString)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
		}

		// Set context
		c.Locals("auth_context", authCtx)
		if authCtx.User != nil {
			c.Locals("auth_type", "user")
			c.Locals("user_id", authCtx.User.UserID)
			// Handle org_id pointer properly
			if authCtx.User.OrganisationID != nil {
				c.Locals("org_id", *authCtx.User.OrganisationID)
			}
			c.Locals("username", authCtx.User.Username)
			c.Locals("role", authCtx.User.Role)
		}
		if authCtx.AuthType == "service" && authCtx.User != nil {
			c.Locals("auth_type", "service")
			c.Locals("service_name", authCtx.User.Username)
			c.Locals("service_id", authCtx.User.UserID)
			c.Locals("permissions", authCtx.User.Permissions)
		}

		return c.Next()
	}
}

func requireRoleMiddleware(allowedRoles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authCtx, ok := c.Locals("auth_context").(*AuthContext)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Authentication required"})
		}

		err := ValidateRole(authCtx, allowedRoles)
		if err != nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
		}

		return c.Next()
	}
}

func requireOrgIsolationMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authType := c.Locals("auth_type")
		
		// Only apply to user authentication (services don't have org restrictions)
		if authType == "user" {
			orgID := c.Locals("org_id")
			if orgID == nil {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "Organization information missing",
				})
			}

			// Set org_id in context for handlers to use for filtering
			c.Locals("organization_id", orgID)
		}

		return c.Next()
	}
}