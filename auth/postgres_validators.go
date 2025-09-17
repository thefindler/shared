package auth

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// =============================================================================
// POSTGRESQL-SPECIFIC VALIDATORS FOR USER_ORG TABLE
// =============================================================================

// These validators work with the standard user_org table schema
// They can be used by any service that uses PostgreSQL with this table structure

// PostgresUserValidator validates users against user_org table
type PostgresUserValidator struct {
	db *pgxpool.Pool
}

// NewPostgresUserValidator creates a new PostgreSQL user validator
func NewPostgresUserValidator(db *pgxpool.Pool) *PostgresUserValidator {
	return &PostgresUserValidator{db: db}
}

func (v *PostgresUserValidator) ValidateUserActive(ctx context.Context, userID, orgID string) error {
	// Parse user ID
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID format")
	}
	
	// Query user from database
	var isActive bool
	var userOrgID *uuid.UUID
	
	query := `SELECT is_active, org_id FROM user_org WHERE id = $1`
	err = v.db.QueryRow(ctx, query, userUUID).Scan(&isActive, &userOrgID)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("database error: %w", err)
	}
	
	// Check if user is active
	if !isActive {
		return fmt.Errorf("user account inactive")
	}
	
	// Verify organization match (if user has org_id and orgID is provided)
	if userOrgID != nil && orgID != "" {
		orgUUID, err := uuid.Parse(orgID)
		if err != nil {
			return fmt.Errorf("invalid organization ID format")
		}
		
		if *userOrgID != orgUUID {
			return fmt.Errorf("user not in specified organization")
		}
	}
	
	return nil
}

func (v *PostgresUserValidator) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	// Basic implementation - returns empty slice
	// Services can extend this if they need user-specific permissions
	return []string{}, nil
}

// PostgresServiceValidator validates services against user_org table
type PostgresServiceValidator struct {
	db *pgxpool.Pool
}

// NewPostgresServiceValidator creates a new PostgreSQL service validator
func NewPostgresServiceValidator(db *pgxpool.Pool) *PostgresServiceValidator {
	return &PostgresServiceValidator{db: db}
}

func (v *PostgresServiceValidator) ValidateServiceActive(ctx context.Context, userID string) error {
	// Query service from database using ID (more secure)
	var isActive bool
	var userType string
	
	query := `SELECT is_active, user_type FROM user_org WHERE id = $1`
	err := v.db.QueryRow(ctx, query, userID).Scan(&isActive, &userType)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("service not found")
		}
		return fmt.Errorf("database error: %w", err)
	}
	
	// Verify it's a service user
	if userType != "service" {
		return fmt.Errorf("user is not a service user")
	}
	
	// Check if service is active
	if !isActive {
		return fmt.Errorf("service account inactive")
	}
	
	return nil
}

func (v *PostgresServiceValidator) ValidateServicePermissions(ctx context.Context, userID string, permissions []string) error {
	// Query service from database using ID (more secure than username)
	var isActive bool
	var userType string
	var userPermissions []string
	
	query := `SELECT is_active, user_type, permissions FROM user_org WHERE id = $1`
	err := v.db.QueryRow(ctx, query, userID).Scan(&isActive, &userType, &userPermissions)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("service not found")
		}
		return fmt.Errorf("database error: %w", err)
	}
	
	// Verify it's a service user
	if userType != "service" {
		return fmt.Errorf("user is not a service user")
	}
	
	// Check if service is active
	if !isActive {
		return fmt.Errorf("service account inactive")
	}
	
	// Check each required permission
	for _, requiredPerm := range permissions {
		hasPermission := false
		for _, userPerm := range userPermissions {
			if userPerm == requiredPerm {
				hasPermission = true
				break
			}
		}
		if !hasPermission {
			return fmt.Errorf("service missing permission: %s", requiredPerm)
		}
	}
	
	return nil
}

// InitializePostgresAuth initializes auth with PostgreSQL validators
func InitializePostgresAuth(db *pgxpool.Pool) error {
	userValidator := NewPostgresUserValidator(db)
	serviceValidator := NewPostgresServiceValidator(db)
	
	config := AuthConfig{
		UserValidator:    userValidator,
		ServiceValidator: serviceValidator,
		CacheConfig:      DefaultCacheConfig(),
	}
	
	return Initialize(config)
}