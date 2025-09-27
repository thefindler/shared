package auth

import (
	"github.com/gofiber/fiber/v2"
)

// AuthHandler wraps the AuthService to provide HTTP handlers.
type AuthHandler struct {
	service *AuthService
}

// NewAuthHandler creates a new handler for auth endpoints.
func NewAuthHandler(service *AuthService) *AuthHandler {
	return &AuthHandler{service: service}
}

func (h *AuthHandler) LoginHandler(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	access, refresh, err := h.service.Login(c.Context(), req.Username, req.Password)
	if err != nil {
		if authErr, ok := err.(*AuthError); ok {
			return c.Status(authErr.Code).JSON(fiber.Map{"error": authErr.Message})
		}
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Login failed"})
	}

	return c.JSON(fiber.Map{
		"access_token":  access,
		"refresh_token": refresh,
	})
}

func (h *AuthHandler) RefreshHandler(c *fiber.Ctx) error {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	token, err := h.service.Refresh(c.Context(), req.RefreshToken)
	if err != nil {
		if authErr, ok := err.(*AuthError); ok {
			return c.Status(authErr.Code).JSON(fiber.Map{"error": authErr.Message})
		}
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Failed to refresh token"})
	}

	return c.JSON(fiber.Map{
		"access_token": token,
	})
}

// CreateUserRequest defines the expected JSON body for creating a user.
type CreateUserRequest struct {
	Username    string   `json:"username" validate:"required,min=3"`
	Password    string   `json:"password" validate:"required,min=8"`
	Role        string   `json:"role" validate:"required,oneof=admin agent-manager agent"`
	UserType    string   `json:"user_type" validate:"required,oneof=user service"`
	Permissions []string `json:"permissions"` // Only applicable for service users
}

// CreateUserHandler handles new user creation.
// It ensures the new user is created within the creating admin's organization.
func (h *AuthHandler) CreateUserHandler(c *fiber.Ctx) error {
	// 1. Get the authenticated admin's context, set by the middleware.
	authCtx, ok := c.Locals(string(AuthContextKey)).(*AuthContext)
	if !ok || authCtx == nil {
		// This should technically be caught by the auth middleware, but it's good practice to check.
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized: Missing authentication context."})
	}

	// Double-check role, although middleware should enforce this. Defense in depth.
	if authCtx.Role != "admin" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden: Only admins can create users."})
	}
	
	// An admin must belong to an organization to create users in it.
	if authCtx.OrganisationID == nil || *authCtx.OrganisationID == "" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden: Admin is not associated with an organization."})
	}

	// 2. Parse and validate the request body
	var req CreateUserRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}
	// TODO: Add struct validation logic here.

	// 3. Call the auth service to create the user, inheriting the admin's OrgID.
	err := h.service.CreateUser(
		c.Context(),
		req.Username,
		req.Password,
		req.Role,
		req.UserType,
		authCtx.OrganisationID, // Inherit OrgID from the authenticated admin
		req.Permissions,
	)
	if err != nil {
		// TODO: Improve error handling to check for specific errors like "username exists".
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create user"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "User created successfully"})
}