package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CameronXie/access-control-explorer/examples/abac/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	UserResource = "user"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

// GetUserIDByEmail retrieves a user ID by email address.
func (r *UserRepository) GetUserIDByEmail(ctx context.Context, email string) (uuid.UUID, error) {
	if email == "" {
		return uuid.Nil, fmt.Errorf("email cannot be empty")
	}

	const query = `SELECT id FROM users WHERE email = $1`

	var userID uuid.UUID
	err := r.pool.QueryRow(ctx, query, email).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, &repository.NotFoundError{
				Resource: UserResource,
				Key:      "email",
				Value:    email,
			}
		}
		return uuid.Nil, fmt.Errorf("query user ID by email %s: %w", email, err)
	}

	return userID, nil
}

// GetUserAttributesByID retrieves user attributes by user ID.
// Returns attributes where roles are guaranteed to be []string type.
// This method implements the UserAttributesRepository interface.
func (r *UserRepository) GetUserAttributesByID(ctx context.Context, id uuid.UUID) (map[string]any, error) {
	type row struct {
		Attributes []byte   `db:"attributes"`
		Roles      []string `db:"roles"`
	}

	// Extract roles as string array, handling different JSON formats
	const query = `
SELECT
  u.attributes,
  CASE jsonb_typeof(u.attributes->'roles')
    WHEN 'array'  THEN ARRAY(SELECT jsonb_array_elements_text(u.attributes->'roles'))
    WHEN 'string' THEN ARRAY[(u.attributes->>'roles')]
    ELSE ARRAY[]::text[]
  END AS roles
FROM users u
WHERE u.id = $1
`
	rows, err := r.pool.Query(ctx, query, id)
	if err != nil {
		return nil, fmt.Errorf("query attributes for user %s: %w", id, err)
	}
	defer rows.Close()

	rec, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[row])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &repository.NotFoundError{
				Resource: UserResource,
				Key:      "id",
				Value:    id.String(),
			}
		}
		return nil, fmt.Errorf("scan attributes for user %s: %w", id, err)
	}

	// Decode JSON attributes
	attrs := make(map[string]any)
	if len(rec.Attributes) > 0 {
		if err := json.Unmarshal(rec.Attributes, &attrs); err != nil {
			return nil, fmt.Errorf("decode attributes for user %s: %w", id, err)
		}
	}
	// Override roles with string array from database query
	attrs["roles"] = rec.Roles

	return attrs, nil
}
