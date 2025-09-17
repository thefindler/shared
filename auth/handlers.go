package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuthHandlers provides all authentication endpoints
type AuthHandlers struct {
	db        *pgxpool.Pool
	validator *validator.Validate
}

// NewAuthHandlers creates a new auth handlers instance
func NewAuthHandlers(db *pgxpool.Pool) *AuthHandlers {
	return &AuthHandlers{
		db:        db,
		validator: validator.New(),
	}
}

// Request/Response models (simplified, focused on auth only)
type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// Legacy - for backward compatibility
type CreateUserRequest struct {
	Username string `json:"username" validate:"required,min=3,max=255"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Role     string `json:"role" validate:"required,oneof=admin agent-manager"`
	// Note: org_id is automatically taken from admin's context for security
}

type CreateServiceUserRequest struct {
	Username    string                 `json:"username" validate:"required,min=3,max=255"`
	Permissions []string               `json:"permissions" validate:"required,min=1"`
	OrgID       *string                `json:"org_id,omitempty"` // Optional - if not provided, uses admin's org_id
	Metadata    map[string]interface{} `json:"metadata"`
}

// Unified user creation request - handles both normal and service users
type CreateUnifiedUserRequest struct {
	Username    string                 `json:"username" validate:"required,min=3,max=255"`
	UserType    string                 `json:"user_type" validate:"required,oneof=normal service"`
	// For normal users
	Email       *string                `json:"email,omitempty" validate:"omitempty,email"`
	Password    *string                `json:"password,omitempty" validate:"omitempty,min=8"`
	Role        *string                `json:"role,omitempty" validate:"omitempty,oneof=admin agent-manager"`
	// For service users
	Permissions []string               `json:"permissions,omitempty"`
	// Common fields
	OrgID       *string                `json:"org_id,omitempty"` // Optional - if not provided, uses admin's org_id
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type LoginResponse struct {
	User         UserResponse `json:"user"`
	RefreshToken string       `json:"refresh_token"`
	TokenType    string       `json:"token_type"`
	ExpiresIn    int          `json:"expires_in"` // Refresh token expiry
}

type UserResponse struct {
	ID       uuid.UUID  `json:"id"`
	Username string     `json:"username"`
	Email    *string    `json:"email,omitempty"`
	OrgID    *uuid.UUID `json:"org_id,omitempty"`
	Role     string     `json:"role"`
	UserType string     `json:"user_type"`
	IsActive bool       `json:"is_active"`
}

type AccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type ServiceTokenResponse struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
	Note      string `json:"note"`
}

// Login handles user login requests
// POST /auth/login
func (h *AuthHandlers) Login(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body: " + err.Error(),
		})
	}

	if err := h.validator.Struct(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Validation failed: " + err.Error(),
		})
	}

	// Get user from database
	user, err := h.getUserByUsername(c.Context(), req.Username)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	// Verify password (only for normal users)
	if user.UserType == "normal" {
		if user.PasswordHash == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid credentials",
			})
		}

		if !VerifyPassword(req.Password, *user.PasswordHash) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid credentials",
			})
		}
	} else {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Service users cannot login with password",
		})
	}

	// Create tokens with unified parameters
	var orgID string
	if user.OrgID != nil {
		orgID = user.OrgID.String()
	}
	
	// Get organization-specific TTL
	_, refreshTTL, err := h.getOrganizationTTL(c.Context(), user.OrgID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get organization TTL",
		})
	}
	
	refreshToken, err := CreateRefreshToken(
		user.ID.String(),
		orgID,
		user.Username,
		user.Role,
		user.UserType,
		user.Permissions,
		refreshTTL,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create refresh token",
		})
	}

	return c.JSON(LoginResponse{
		User: UserResponse{
			ID:       user.ID,
			Username: user.Username,
			Email:    user.Email,
			OrgID:    user.OrgID,
			Role:     user.Role,
			UserType: user.UserType,
			IsActive: user.IsActive,
		},
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(refreshTTL.Seconds()), // Refresh token expiry
	})
}

// RefreshToken handles access token refresh requests
// POST /auth/refresh
func (h *AuthHandlers) RefreshToken(c *fiber.Ctx) error {
	var req RefreshTokenRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body: " + err.Error(),
		})
	}

	if err := h.validator.Struct(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Validation failed: " + err.Error(),
		})
	}

	// Validate refresh token
	userClaims, err := ValidateToken(req.RefreshToken)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid refresh token",
		})
	}

	if userClaims.TokenType != RefreshToken {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid token type",
		})
	}

	// Check if user is still active
	user, err := h.getUserByID(c.Context(), userClaims.UserID)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	if !user.IsActive {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "User account inactive",
		})
	}

	// Create new access token
	var orgID string
	if user.OrgID != nil {
		orgID = user.OrgID.String()
	}
	
	// Get organization-specific TTL
	accessTTL, _, err := h.getOrganizationTTL(c.Context(), user.OrgID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get organization TTL",
		})
	}
	
	accessToken, err := CreateAccessToken(
		user.ID.String(),
		orgID,
		user.Username,
		user.Role,
		user.UserType,
		user.Permissions,
		accessTTL,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create access token",
		})
	}

	return c.JSON(AccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(GetJWTConfig().AccessTokenExpiry.Seconds()),
	})
}

// Logout handles user logout requests
// POST /auth/logout
func (h *AuthHandlers) Logout(c *fiber.Ctx) error {
	var req RefreshTokenRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body: " + err.Error(),
		})
	}

	// For now, logout just validates the token exists
	// In a more complex system, we might blacklist the token
	_, err := ValidateToken(req.RefreshToken)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid token",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Logout successful",
	})
}

// CreateNormalUser handles normal user creation requests (admin only)
// POST /auth/users
func (h *AuthHandlers) CreateNormalUser(c *fiber.Ctx) error {
	var req CreateUserRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body: " + err.Error(),
		})
	}

	if err := h.validator.Struct(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Validation failed: " + err.Error(),
		})
	}

	// Get current user ID from context
	var createdBy *uuid.UUID
	if userID := c.Locals("user_id"); userID != nil {
		if userIDStr, ok := userID.(string); ok {
			if parsedID, err := uuid.Parse(userIDStr); err == nil {
				createdBy = &parsedID
			}
		}
	}

	// Check if username already exists
	exists, err := h.existsByUsername(c.Context(), req.Username)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}
	if exists {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Username already exists",
		})
	}

	// Check if email already exists
	exists, err = h.existsByEmail(c.Context(), req.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}
	if exists {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Email already exists",
		})
	}

	// Get organization ID from context (set by organization isolation middleware)
	// This ensures admin can only create users in their own organization
	orgID, ok := c.Locals("organization_id").(string)
	if !ok {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Organization context missing - admin must belong to an organization",
		})
	}

	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Invalid organization ID format",
		})
	}

	// Hash password
	hashedPassword, err := HashPassword(req.Password)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to process password",
		})
	}

	// Create user in admin's organization (security: prevents cross-org user creation)
	user, err := h.createNormalUser(c.Context(), &req, orgUUID, hashedPassword, createdBy)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "User created successfully",
		"user": UserResponse{
			ID:       user.ID,
			Username: user.Username,
			Email:    user.Email,
			OrgID:    user.OrgID,
			Role:     user.Role,
			UserType: user.UserType,
			IsActive: user.IsActive,
		},
	})
}

// CreateServiceUser handles service user creation requests (admin only)
// POST /auth/service/user
func (h *AuthHandlers) CreateServiceUser(c *fiber.Ctx) error {
	var req CreateServiceUserRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body: " + err.Error(),
		})
	}

	if err := h.validator.Struct(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Validation failed: " + err.Error(),
		})
	}

	// Get current user ID from context
	var createdBy *uuid.UUID
	if userID := c.Locals("user_id"); userID != nil {
		if userIDStr, ok := userID.(string); ok {
			if parsedID, err := uuid.Parse(userIDStr); err == nil {
				createdBy = &parsedID
			}
		}
	}

	// Check if username already exists
	exists, err := h.existsByUsername(c.Context(), req.Username)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database error",
		})
	}
	if exists {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Username already exists",
		})
	}

	// Get admin's org_id from context (for service user assignment)
	var adminOrgID *uuid.UUID
	if orgID := c.Locals("org_id"); orgID != nil {
		if orgIDStr, ok := orgID.(string); ok {
			if parsedID, err := uuid.Parse(orgIDStr); err == nil {
				adminOrgID = &parsedID
			}
		}
	}
	
	// If org_id not provided in request, use admin's org_id
	var serviceOrgID *uuid.UUID
	if req.OrgID != nil && *req.OrgID != "" {
		if parsedID, err := uuid.Parse(*req.OrgID); err == nil {
			serviceOrgID = &parsedID
		}
	} else {
		serviceOrgID = adminOrgID
	}

	// Create service user with organization ID
	user, err := h.createServiceUser(c.Context(), &req, serviceOrgID, createdBy)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Get organization-specific TTL for service token
	_, refreshTTL, err := h.getOrganizationTTL(c.Context(), serviceOrgID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get organization TTL",
		})
	}

	// Create service token with organization-specific TTL
	serviceToken, err := CreateServiceToken(
		user.Username,
		user.ID.String(),
		req.Permissions,
		refreshTTL,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create service token",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "Service user created successfully",
		"service_token": ServiceTokenResponse{
			Token:     serviceToken,
			TokenType: "Bearer",
			ExpiresIn: int(refreshTTL.Seconds()),
			Note:      "Store this service token securely. It will not be shown again.",
		},
	})
}

// GetAvailablePermissions returns the list of available service permissions
// GET /auth/service/permissions
func (h *AuthHandlers) GetAvailablePermissions(c *fiber.Ctx) error {
	permissions := []string{
		"call.callback",
		"call.webhook",
		"call.create",
		"call.update",
		"agent.read",
		"agent.update",
		"conversation.read",
		"conversation.update",
	}

	return c.JSON(fiber.Map{
		"permissions": permissions,
		"description": map[string]string{
			"call.callback":       "Handle call callbacks from external services",
			"call.webhook":        "Receive call status webhooks",
			"call.create":         "Create new calls",
			"call.update":         "Update call status",
			"agent.read":          "Read agent information",
			"agent.update":        "Update agent information",
			"conversation.read":   "Read conversation data",
			"conversation.update": "Update conversation data",
		},
	})
}

// Database helper functions (simplified, direct SQL)

type UserDB struct {
	ID           uuid.UUID              `db:"id"`
	Username     string                 `db:"username"`
	Email        *string                `db:"email"`
	PasswordHash *string                `db:"password_hash"`
	OrgID        *uuid.UUID             `db:"org_id"`
	Role         string                 `db:"role"`
	UserType     string                 `db:"user_type"`
	IsActive     bool                   `db:"is_active"`
	Permissions  []string               `db:"service_permissions"`
	Metadata     map[string]interface{} `db:"service_metadata"`
}

func (h *AuthHandlers) getUserByUsername(ctx context.Context, username string) (*UserDB, error) {
	var user UserDB
	query := `
		SELECT id, username, email, password_hash, org_id, role, user_type, permissions, is_active
		FROM user_org 
		WHERE username = $1 AND is_active = true`

	err := h.db.QueryRow(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.OrgID, &user.Role, &user.UserType, &user.Permissions, &user.IsActive,
	)
	if err != nil {
		return nil, fmt.Errorf("user not found: %s", username)
	}

	return &user, nil
}

func (h *AuthHandlers) getUserByID(ctx context.Context, userID string) (*UserDB, error) {
	var user UserDB
	parsedID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID format")
	}

	query := `
		SELECT id, username, email, password_hash, org_id, role, user_type, permissions, is_active
		FROM user_org 
		WHERE id = $1 AND is_active = true`

	err = h.db.QueryRow(ctx, query, parsedID).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.OrgID, &user.Role, &user.UserType, &user.Permissions, &user.IsActive,
	)
	if err != nil {
		return nil, fmt.Errorf("user not found: %s", userID)
	}

	return &user, nil
}

func (h *AuthHandlers) existsByUsername(ctx context.Context, username string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM user_org WHERE username = $1)`
	err := h.db.QueryRow(ctx, query, username).Scan(&exists)
	return exists, err
}

func (h *AuthHandlers) existsByEmail(ctx context.Context, email string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM user_org WHERE email = $1)`
	err := h.db.QueryRow(ctx, query, email).Scan(&exists)
	return exists, err
}

func (h *AuthHandlers) createNormalUser(ctx context.Context, req *CreateUserRequest, orgID uuid.UUID, hashedPassword string, createdBy *uuid.UUID) (*UserDB, error) {
	user := &UserDB{
		ID:           uuid.New(),
		Username:     req.Username,
		Email:        &req.Email,
		PasswordHash: &hashedPassword,
		OrgID:        &orgID,
		Role:         req.Role,
		UserType:     "normal",
		IsActive:     true,
	}

	query := `
		INSERT INTO user_org (id, username, email, password_hash, org_id, role, user_type, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := h.db.Exec(ctx, query,
		user.ID, user.Username, user.Email, user.PasswordHash, user.OrgID,
		user.Role, user.UserType, user.IsActive,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

func (h *AuthHandlers) createServiceUser(ctx context.Context, req *CreateServiceUserRequest, orgID *uuid.UUID, createdBy *uuid.UUID) (*UserDB, error) {
	user := &UserDB{
		ID:          uuid.New(),
		Username:    req.Username,
		OrgID:       orgID, // Set organization ID
		Role:        "service",
		UserType:    "service",
		IsActive:    true,
		Permissions: req.Permissions,
		Metadata:    req.Metadata,
	}

	if user.Metadata == nil {
		user.Metadata = make(map[string]interface{})
	}

	query := `
		INSERT INTO user_org (id, username, org_id, role, user_type, permissions, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := h.db.Exec(ctx, query,
		user.ID, user.Username, user.OrgID, user.Role, user.UserType,
		user.Permissions, user.IsActive,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create service user: %w", err)
	}

	return user, nil
}

// getOrganizationTTL retrieves TTL values from organization table
func (h *AuthHandlers) getOrganizationTTL(ctx context.Context, orgID *uuid.UUID) (accessTTL, refreshTTL time.Duration, err error) {
	// Default TTL for global services (no organization)
	if orgID == nil {
		return 4 * time.Hour, 8760 * time.Hour, nil // 4 hours access, 1 year refresh
	}
	
	var accessHours, refreshHours int
	query := `
		SELECT access_token_ttl_hours, refresh_token_ttl_hours 
		FROM organisation 
		WHERE id = $1`
	
	err = h.db.QueryRow(ctx, query, orgID).Scan(&accessHours, &refreshHours)
	if err != nil {
		// If organization not found, use defaults
		return 4 * time.Hour, 8760 * time.Hour, nil
	}
	
	return time.Duration(accessHours) * time.Hour, time.Duration(refreshHours) * time.Hour, nil
}