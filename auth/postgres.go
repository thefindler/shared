import (
	"context"
	"database/sql"
	"time"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lib/pq"
)

type PostgresDB struct {
	pool *pgxpool.Pool
}

func NewPostgresDB(pool *pgxpool.Pool) *PostgresDB {
	return &PostgresDB{pool: pool}
}

func (p *PostgresDB) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	user := &User{}
	query := `
		SELECT id, organisation_id, username, role, user_type, permissions, password_hash, is_active
		FROM user_org WHERE username = $1`

	err := p.pool.QueryRow(ctx, query, username).Scan(
		&user.ID, &user.OrganisationID, &user.Username, &user.Role,
		&user.UserType, pq.Array(&user.Permissions), &user.PasswordHash, &user.IsActive,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	return user, err
}

func (p *PostgresDB) GetUserByID(ctx context.Context, userID string) (*User, error) {
	user := &User{}
	query := `
		SELECT id, organisation_id, username, role, user_type, permissions, password_hash, is_active
		FROM user_org WHERE id = $1`

	err := p.pool.QueryRow(ctx, query, userID).Scan(
		&user.ID, &user.OrganisationID, &user.Username, &user.Role,
		&user.UserType, pq.Array(&user.Permissions), &user.PasswordHash, &user.IsActive,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	return user, err
}

func (p *PostgresDB) CreateUser(ctx context.Context, user *User) error {
	query := `
		INSERT INTO user_org (id, organisation_id, username, role, user_type, permissions, password_hash, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := p.pool.Exec(ctx, query,
		user.ID, user.OrganisationID, user.Username, user.Role,
		user.UserType, pq.Array(user.Permissions), user.PasswordHash, user.IsActive,
	)
	return err
}

// GetOrgConfig gets organization-specific auth settings
func (p *PostgresDB) GetOrgConfig(ctx context.Context, orgID *string) (*OrgConfig, error) {
	// Default config for global users (no org)
	defaultConfig := &OrgConfig{
		AccessTokenTTL:  4 * time.Hour,
		RefreshTokenTTL: 365 * 24 * time.Hour, // 365 days
	}

	if orgID == nil {
		return defaultConfig, nil
	}

	var accessHours, refreshHours int
	query := `SELECT access_token_ttl_hours, refresh_token_ttl_hours FROM organization WHERE id = $1`

	err := p.pool.QueryRow(ctx, query, *orgID).Scan(&accessHours, &refreshHours)
	if err != nil {
		// If org not found, use defaults
		return defaultConfig, nil
	}

	return &OrgConfig{
		AccessTokenTTL:  time.Duration(accessHours) * time.Hour,
		RefreshTokenTTL: time.Duration(refreshHours) * time.Hour,
	}, nil
}

// IsTokenDenied checks if a token JTI is in the blacklist
func (p *PostgresDB) IsTokenDenied(ctx context.Context, jti string) (bool, error) {
	var count int
	err := p.pool.QueryRow(ctx, 
		"SELECT COUNT(*) FROM denied_tokens WHERE jti = $1 AND expires_at > NOW()", 
		jti).Scan(&count)
	return count > 0, err
}

// DenyToken adds a token JTI to the blacklist
func (p *PostgresDB) DenyToken(ctx context.Context, jti string, expiresAt time.Time) error {
	_, err := p.pool.Exec(ctx, 
		"INSERT INTO denied_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING", 
		jti, expiresAt)
	return err
}

// ValidateUserActive checks if a user is present and active in the database.
func (p *PostgresDB) ValidateUserActive(ctx context.Context, userID string, orgID string) error {
	user, err := p.GetUserByID(ctx, userID)
	if err != nil {
		return ErrUserInactive // Assuming not found means inactive for this purpose
	}
	if !user.IsActive {
		return ErrUserInactive
	}
	// Optionally, you could also validate if user.OrganisationID matches orgID
	return nil
}

// ValidateServiceActive checks if a service account is present and active.
func (p *PostgresDB) ValidateServiceActive(ctx context.Context, serviceID string) error {
	// Assuming services are also stored in the user_org table with a specific user_type
	service, err := p.GetUserByID(ctx, serviceID)
	if err != nil {
		return ErrServiceInactive
	}
	if !service.IsActive || service.UserType != "service" {
		return ErrServiceInactive
	}
	return nil
}
