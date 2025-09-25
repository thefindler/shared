package auth

import (
	"context"
	"encoding/json"

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

// CreateUserHandler handles new user creation. This is a protected endpoint.
func (h *AuthHandler) CreateUserHandler(c *fiber.Ctx) error {
	// Authorization is now handled by the middleware that wraps this handler.
	var req struct {
		Username    string   `json:"username"`
		Password    string   `json:"password"`
		Role        string   `json:"role"`
		UserType    string   `json:"user_type"`
		OrgID       *string  `json:"organisation_id"`
		Permissions []string `json:"permissions"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	err := h.service.CreateUser(c.Context(), req.Username, req.Password, req.Role, req.UserType, req.OrgID, req.Permissions)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.SendStatus(fiber.StatusCreated)
}