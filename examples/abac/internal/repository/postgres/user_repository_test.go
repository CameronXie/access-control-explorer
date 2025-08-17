//nolint:dupl // unit tests
package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/CameronXie/access-control-explorer/examples/abac/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testUser struct {
	id         uuid.UUID
	email      string
	attributes map[string]any
}

func TestUserRepository_GetUserIDByEmail(t *testing.T) {
	pool := setupTestDBForUsers(t)
	defer pool.Close()

	userID := uuid.New()
	anotherUserID := uuid.New()
	nonExistentEmail := "nonexistent@example.com"

	testCases := map[string]struct {
		email             string
		testUsers         []testUser
		setupContext      func() context.Context
		expectedResult    uuid.UUID
		expectedError     string
		expectNotFoundErr bool
	}{
		"should return user ID when user exists with email": {
			email: "john.doe@example.com",
			testUsers: []testUser{
				{
					id:    userID,
					email: "john.doe@example.com",
					attributes: map[string]any{
						"roles":      []string{"admin", "user"},
						"department": "engineering",
					},
				},
			},
			setupContext:   func() context.Context { return context.Background() },
			expectedResult: userID,
		},

		"should return correct user ID when user exists": {
			email: "jane.smith@example.com",
			testUsers: []testUser{
				{
					id:    userID,
					email: "jane.smith@example.com",
					attributes: map[string]any{
						"roles":      []string{"manager"},
						"department": "sales",
					},
				},
			},
			setupContext:   func() context.Context { return context.Background() },
			expectedResult: userID,
		},

		"should return user ID even with empty attributes": {
			email: "empty.user@example.com",
			testUsers: []testUser{
				{
					id:    userID,
					email: "empty.user@example.com",
				},
			},
			setupContext:   func() context.Context { return context.Background() },
			expectedResult: userID,
		},

		"should return NotFoundError when user does not exist": {
			email: nonExistentEmail,
			testUsers: []testUser{
				{
					id:    userID,
					email: "existing.user@example.com",
					attributes: map[string]any{
						"roles": []string{"user"},
					},
				},
			},
			setupContext:      func() context.Context { return context.Background() },
			expectedResult:    uuid.Nil,
			expectedError:     fmt.Sprintf("user with email %s not found", nonExistentEmail),
			expectNotFoundErr: true,
		},

		"should return error when email is empty": {
			email: "",
			testUsers: []testUser{
				{
					id:    userID,
					email: "test.user@example.com",
					attributes: map[string]any{
						"roles": []string{"user"},
					},
				},
			},
			setupContext:   func() context.Context { return context.Background() },
			expectedResult: uuid.Nil,
			expectedError:  "email cannot be empty",
		},

		"should return error when context is cancelled": {
			email: "context.test@example.com",
			testUsers: []testUser{
				{
					id:    userID,
					email: "context.test@example.com",
					attributes: map[string]any{
						"roles": []string{"user"},
					},
				},
			},
			setupContext: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			expectedResult: uuid.Nil,
			expectedError:  "context canceled",
		},

		"should handle multiple users but return correct ID": {
			email: "target.user@example.com",
			testUsers: []testUser{
				{
					id:    anotherUserID,
					email: "other.user@example.com",
					attributes: map[string]any{
						"roles": []string{"guest"},
					},
				},
				{
					id:    userID,
					email: "target.user@example.com",
					attributes: map[string]any{
						"roles": []string{"admin"},
					},
				},
			},
			setupContext:   func() context.Context { return context.Background() },
			expectedResult: userID,
		},

		"should return ID regardless of attribute complexity": {
			email: "complex.user@example.com",
			testUsers: []testUser{
				{
					id:    userID,
					email: "complex.user@example.com",
					attributes: map[string]any{
						"roles":        []string{"admin", "user", "moderator"},
						"department":   "engineering",
						"team_members": 15,
						"budget_limit": 50000.75,
						"preferences": map[string]any{
							"theme":    "dark",
							"language": "en",
							"notifications": map[string]any{
								"email": true,
								"sms":   false,
							},
						},
					},
				},
			},
			setupContext:   func() context.Context { return context.Background() },
			expectedResult: userID,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			repo := NewUserRepository(pool)

			// Setup test data
			setupTestUsersData(t, pool, tc.testUsers)

			// Setup context
			ctx := tc.setupContext()

			// Execute
			result, err := repo.GetUserIDByEmail(ctx, tc.email)

			// Assert
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Equal(t, uuid.Nil, result)

				// Test custom NotFoundError type
				if tc.expectNotFoundErr {
					var notFoundErr *repository.NotFoundError
					assert.True(t, errors.As(err, &notFoundErr))
					assert.Equal(t, UserResource, notFoundErr.Resource)
					assert.Equal(t, "email", notFoundErr.Key)
					assert.Equal(t, tc.email, notFoundErr.Value)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
			}

			// Clean up test data
			cleanupTestUsersData(t, pool)
		})
	}
}

func TestUserRepository_GetUserAttributesByID(t *testing.T) {
	pool := setupTestDBForUsers(t)
	defer pool.Close()

	userID := uuid.New()
	anotherUserID := uuid.New()
	nonExistentID := uuid.New()

	testCases := map[string]struct {
		id                uuid.UUID
		testUsers         []testUser
		setupContext      func() context.Context
		expectedResult    map[string]any
		expectedError     string
		expectNotFoundErr bool
	}{
		"should return attributes when user exists with ID": {
			id: userID,
			testUsers: []testUser{
				{
					id:    userID,
					email: "john.doe@example.com",
					attributes: map[string]any{
						"roles":      []string{"admin", "user"},
						"department": "engineering",
						"region":     "north_america",
						"level":      "senior",
						"permissions": map[string]any{
							"read":  true,
							"write": true,
							"admin": true,
						},
					},
				},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: map[string]any{
				"roles":      []string{"admin", "user"},
				"department": "engineering",
				"region":     "north_america",
				"level":      "senior",
				"permissions": map[string]any{
					"read":  true,
					"write": true,
					"admin": true,
				},
			},
		},

		"should return attributes with complex nested data": {
			id: userID,
			testUsers: []testUser{
				{
					id:    userID,
					email: "jane.smith@example.com",
					attributes: map[string]any{
						"roles":        []string{"manager", "reviewer"},
						"department":   "sales",
						"region":       "europe",
						"level":        "manager",
						"team_members": 15,
						"budget_limit": 50000.75,
						"preferences": map[string]any{
							"theme":    "dark",
							"language": "en",
							"timezone": "UTC+1",
							"notifications": map[string]any{
								"email": true,
								"sms":   false,
								"push":  true,
							},
						},
					},
				},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: map[string]any{
				"roles":        []string{"manager", "reviewer"},
				"department":   "sales",
				"region":       "europe",
				"level":        "manager",
				"team_members": float64(15),
				"budget_limit": 50000.75,
				"preferences": map[string]any{
					"theme":    "dark",
					"language": "en",
					"timezone": "UTC+1",
					"notifications": map[string]any{
						"email": true,
						"sms":   false,
						"push":  true,
					},
				},
			},
		},

		"should return empty attributes map when user has no attributes": {
			id: userID,
			testUsers: []testUser{
				{
					id:    userID,
					email: "empty.user@example.com",
				},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: map[string]any{
				"roles": []string{},
			},
		},

		"should handle roles as single string value": {
			id: userID,
			testUsers: []testUser{
				{
					id:    userID,
					email: "single.role@example.com",
					attributes: map[string]any{
						"roles":      "admin", // Single string instead of array
						"department": "it",
						"active":     true,
					},
				},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: map[string]any{
				"roles":      []string{"admin"},
				"department": "it",
				"active":     true,
			},
		},

		"should handle missing roles field gracefully": {
			id: userID,
			testUsers: []testUser{
				{
					id:    userID,
					email: "no.roles@example.com",
					attributes: map[string]any{
						"department": "hr",
						"level":      "junior",
						"active":     true,
					},
				},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: map[string]any{
				"roles":      []string{},
				"department": "hr",
				"level":      "junior",
				"active":     true,
			},
		},

		"should return NotFoundError when user does not exist": {
			id: nonExistentID,
			testUsers: []testUser{
				{
					id:    userID,
					email: "existing.user@example.com",
					attributes: map[string]any{
						"roles":      []string{"user"},
						"department": "support",
					},
				},
			},
			setupContext:      func() context.Context { return context.Background() },
			expectedResult:    nil,
			expectedError:     fmt.Sprintf("user with id %s not found", nonExistentID.String()),
			expectNotFoundErr: true,
		},

		"should return error when context is cancelled": {
			id: userID,
			testUsers: []testUser{
				{
					id:    userID,
					email: "context.test@example.com",
					attributes: map[string]any{
						"roles":      []string{"user"},
						"department": "testing",
					},
				},
			},
			setupContext: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			expectedResult: nil,
			expectedError:  "context canceled",
		},

		"should handle multiple users but return correct attributes": {
			id: userID,
			testUsers: []testUser{
				{
					id:    anotherUserID,
					email: "other.user@example.com",
					attributes: map[string]any{
						"roles":      []string{"guest"},
						"department": "other",
					},
				},
				{
					id:    userID,
					email: "target.user@example.com",
					attributes: map[string]any{
						"roles":      []string{"admin"},
						"department": "target",
						"priority":   "high",
						"clearance":  "level5",
					},
				},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: map[string]any{
				"roles":      []string{"admin"},
				"department": "target",
				"priority":   "high",
				"clearance":  "level5",
			},
		},

		"should handle arrays with mixed content correctly": {
			id: userID,
			testUsers: []testUser{
				{
					id:    userID,
					email: "mixed.array@example.com",
					attributes: map[string]any{
						"roles":        []string{"admin", "user", "moderator"},
						"numbers":      []int{1, 2, 3},
						"mixed_values": []any{"string", 42, true, 3.14},
						"department":   "mixed",
					},
				},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: map[string]any{
				"roles":        []string{"admin", "user", "moderator"},
				"numbers":      []any{float64(1), float64(2), float64(3)},
				"mixed_values": []any{"string", float64(42), true, 3.14},
				"department":   "mixed",
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			repo := NewUserRepository(pool)

			// Setup test data
			setupTestUsersData(t, pool, tc.testUsers)

			// Setup context
			ctx := tc.setupContext()

			// Execute
			result, err := repo.GetUserAttributesByID(ctx, tc.id)

			// Assert
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, result)

				// Test custom NotFoundError type
				if tc.expectNotFoundErr {
					var notFoundErr *repository.NotFoundError
					assert.True(t, errors.As(err, &notFoundErr))
					assert.Equal(t, UserResource, notFoundErr.Resource)
					assert.Equal(t, "id", notFoundErr.Key)
					assert.Equal(t, tc.id.String(), notFoundErr.Value)
				}
			} else {
				assert.NoError(t, err)
				assert.EqualValues(t, tc.expectedResult, result)
			}

			// Clean up test data
			cleanupTestUsersData(t, pool)
		})
	}
}

func setupTestDBForUsers(t *testing.T) *pgxpool.Pool {
	pg := fmt.Sprintf(
		"postgres://%s:%s@%s/%s?sslmode=%s",
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_HOST"),
		os.Getenv("POSTGRES_DB_TEST"),
		os.Getenv("POSTGRES_SSL"),
	)

	pool, err := pgxpool.New(context.Background(), pg)
	require.NoError(t, err)
	return pool
}

func setupTestUsersData(t *testing.T, pool *pgxpool.Pool, users []testUser) {
	for _, user := range users {
		if user.attributes == nil {
			_, err := pool.Exec(
				context.Background(),
				"INSERT INTO users (id, email) VALUES ($1, $2)",
				user.id, user.email,
			)
			require.NoError(t, err)
			continue
		}

		_, err := pool.Exec(
			context.Background(),
			"INSERT INTO users (id, email, attributes) VALUES ($1, $2, $3)",
			user.id, user.email, user.attributes,
		)
		require.NoError(t, err)
	}
}

func cleanupTestUsersData(t *testing.T, pool *pgxpool.Pool) {
	_, err := pool.Exec(context.Background(), "TRUNCATE TABLE users")
	require.NoError(t, err)
}
