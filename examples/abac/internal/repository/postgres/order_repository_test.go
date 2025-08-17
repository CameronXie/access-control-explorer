//nolint:dupl // unit tests
package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/CameronXie/access-control-explorer/examples/abac/internal/domain"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testOrder struct {
	id         uuid.UUID
	name       string
	attributes map[string]any
}

func TestOrderRepository_CreateOrder(t *testing.T) {
	pool := setupTestDBForOrders(t)
	defer pool.Close()

	orderID := uuid.New()
	testCases := map[string]struct {
		order         *domain.Order
		setupContext  func() context.Context
		expectedError string
		verifyInDB    bool
	}{

		"should create order with empty attributes": {
			order: &domain.Order{
				ID:         orderID,
				Name:       "Basic Order",
				Attributes: map[string]any{},
			},
			setupContext: func() context.Context { return context.Background() },
			verifyInDB:   true,
		},

		"should create order with complex nested attributes": {
			order: &domain.Order{
				ID:   orderID,
				Name: "Enterprise Solution",
				Attributes: map[string]any{
					"category":      "enterprise",
					"price":         1999.50,
					"currency":      "EUR",
					"status":        "pending",
					"quantity":      float64(5),
					"discount_rate": 0.15,
					"metadata": map[string]any{
						"source":   "web",
						"campaign": "summer2024",
						"referrer": "partner_site",
						"custom_fields": map[string]any{
							"priority":      "high",
							"rush_order":    true,
							"special_notes": "Handle with care",
						},
					},
				},
			},
			setupContext: func() context.Context { return context.Background() },
			verifyInDB:   true,
		},

		"should return error when context is cancelled": {
			order: &domain.Order{
				ID:   orderID,
				Name: "Context Test Order",
				Attributes: map[string]any{
					"category": "test",
					"price":    49.99,
				},
			},
			setupContext: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			expectedError: "context canceled",
			verifyInDB:    false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			repo := NewOrderRepository(pool)

			// Setup context
			ctx := tc.setupContext()

			// Execute
			err := repo.CreateOrder(ctx, tc.order)

			// Assert
			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				assert.NoError(t, err)
			}

			// Verify in database if expected
			if tc.verifyInDB && err == nil {
				retrievedOrder, err := repo.GetOrderByID(context.Background(), tc.order.ID)
				assert.NoError(t, err)
				assert.EqualValues(t, tc.order, retrievedOrder)
			}

			// Clean up test data
			cleanupTestOrdersData(t, pool)
		})
	}
}

func TestOrderRepository_GetOrderByID(t *testing.T) {
	pool := setupTestDBForOrders(t)
	defer pool.Close()

	orderID := uuid.New()
	anotherOrderID := uuid.New()
	nonExistentID := uuid.New()

	testCases := map[string]struct {
		id                uuid.UUID
		testOrders        []testOrder
		expectedResult    *domain.Order
		expectedError     string
		expectNotFoundErr bool
	}{
		"should return order with complex attributes": {
			id: orderID,
			testOrders: []testOrder{
				{
					id:   orderID,
					name: "Enterprise Solution",
					attributes: map[string]any{
						"category":      "enterprise",
						"price":         1999.50,
						"currency":      "EUR",
						"status":        "pending",
						"quantity":      5,
						"discount_rate": 0.15,
						"metadata": map[string]any{
							"source":   "web",
							"campaign": "summer2024",
							"referrer": "partner_site",
							"custom_fields": map[string]any{
								"priority":      "high",
								"rush_order":    true,
								"special_notes": "Handle with care",
							},
						},
					},
				},
			},
			expectedResult: &domain.Order{
				ID:   orderID,
				Name: "Enterprise Solution",
				Attributes: map[string]any{
					"category":      "enterprise",
					"price":         1999.50,
					"currency":      "EUR",
					"status":        "pending",
					"quantity":      float64(5),
					"discount_rate": 0.15,
					"metadata": map[string]any{
						"source":   "web",
						"campaign": "summer2024",
						"referrer": "partner_site",
						"custom_fields": map[string]any{
							"priority":      "high",
							"rush_order":    true,
							"special_notes": "Handle with care",
						},
					},
				},
			},
		},

		"should return order with empty attributes": {
			id: orderID,
			testOrders: []testOrder{
				{
					id:   orderID,
					name: "Basic Order",
				},
			},
			expectedResult: &domain.Order{
				ID:         orderID,
				Name:       "Basic Order",
				Attributes: map[string]any{},
			},
		},

		"should return NotFoundError when order does not exist": {
			id: nonExistentID,
			testOrders: []testOrder{
				{
					id:   orderID,
					name: "Existing Order",
					attributes: map[string]any{
						"category": "standard",
						"price":    99.99,
					},
				},
			},
			expectedResult:    nil,
			expectedError:     fmt.Sprintf("order with id %s not found", nonExistentID.String()),
			expectNotFoundErr: true,
		},

		"should handle multiple orders but return correct one": {
			id: orderID,
			testOrders: []testOrder{
				{
					id:   anotherOrderID,
					name: "Other Order",
					attributes: map[string]any{
						"category": "other",
						"price":    199.99,
					},
				},
				{
					id:   orderID,
					name: "Target Order",
					attributes: map[string]any{
						"category": "target",
						"price":    399.99,
						"priority": "high",
					},
				},
			},
			expectedResult: &domain.Order{
				ID:   orderID,
				Name: "Target Order",
				Attributes: map[string]any{
					"category": "target",
					"price":    399.99,
					"priority": "high",
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			repo := NewOrderRepository(pool)

			// Setup test data
			setupTestOrdersData(t, pool, tc.testOrders)

			// Execute
			result, err := repo.GetOrderByID(context.Background(), tc.id)

			// Assert
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, result)

				// Test custom NotFoundError type
				if tc.expectNotFoundErr {
					var notFoundErr *repository.NotFoundError
					assert.True(t, errors.As(err, &notFoundErr))
					assert.Equal(t, OrderResource, notFoundErr.Resource)
					assert.Equal(t, "id", notFoundErr.Key)
					assert.Equal(t, tc.id.String(), notFoundErr.Value)

					// Test errors.Is functionality
					var notFoundError *repository.NotFoundError
					assert.True(t, errors.As(err, &notFoundError))
				}
			} else {
				assert.NoError(t, err)
				assert.EqualValues(t, tc.expectedResult, result)
			}

			// Clean up test data
			cleanupTestOrdersData(t, pool)
		})
	}
}

func TestOrderRepository_GetOrderAttributesByID(t *testing.T) {
	pool := setupTestDBForOrders(t)
	defer pool.Close()

	orderID := uuid.New()
	anotherOrderID := uuid.New()
	nonExistentID := uuid.New()

	testCases := map[string]struct {
		id                uuid.UUID
		testOrders        []testOrder
		setupContext      func() context.Context
		expectedResult    map[string]any
		expectedError     string
		expectNotFoundErr bool
	}{
		"should return attributes when order exists with ID": {
			id: orderID,
			testOrders: []testOrder{
				{
					id:   orderID,
					name: "Complex Order",
					attributes: map[string]any{
						"category":    "premium",
						"price":       2499.99,
						"currency":    "USD",
						"total_items": 15,
						"customer": map[string]any{
							"id":       "cust_123",
							"name":     "John Doe",
							"tier":     "gold",
							"contacts": []string{"email", "sms", "push"},
						},
						"metadata": map[string]any{
							"source":     "mobile_app",
							"campaign":   "holiday2024",
							"processing": true,
							"tags":       []string{"urgent", "vip", "express"},
							"analytics": map[string]any{
								"conversion_rate": 0.85,
								"session_id":      "sess_789",
								"utm_source":      "google",
							},
						},
					},
				},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: map[string]any{
				"category":    "premium",
				"price":       2499.99,
				"currency":    "USD",
				"total_items": float64(15),
				"customer": map[string]any{
					"id":       "cust_123",
					"name":     "John Doe",
					"tier":     "gold",
					"contacts": []any{"email", "sms", "push"},
				},
				"metadata": map[string]any{
					"source":     "mobile_app",
					"campaign":   "holiday2024",
					"processing": true,
					"tags":       []any{"urgent", "vip", "express"},
					"analytics": map[string]any{
						"conversion_rate": 0.85,
						"session_id":      "sess_789",
						"utm_source":      "google",
					},
				},
			},
		},

		"should return empty map when order has no attributes": {
			id: orderID,
			testOrders: []testOrder{
				{
					id:   orderID,
					name: "Basic Order",
				},
			},
			setupContext:   func() context.Context { return context.Background() },
			expectedResult: map[string]any{},
		},

		"should handle mixed data types correctly": {
			id: orderID,
			testOrders: []testOrder{
				{
					id:   orderID,
					name: "Mixed Data Order",
					attributes: map[string]any{
						"string_field":  "hello world",
						"number_field":  42,
						"float_field":   3.14159,
						"bool_field":    true,
						"null_field":    nil,
						"array_numbers": []int{1, 2, 3, 4, 5},
						"array_mixed":   []any{"text", 123, false, 99.9},
						"nested": map[string]any{
							"level1": map[string]any{
								"level2": "deep value",
								"array":  []string{"a", "b", "c"},
							},
						},
					},
				},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: map[string]any{
				"string_field":  "hello world",
				"number_field":  float64(42),
				"float_field":   3.14159,
				"bool_field":    true,
				"null_field":    nil,
				"array_numbers": []any{float64(1), float64(2), float64(3), float64(4), float64(5)},
				"array_mixed":   []any{"text", float64(123), false, 99.9},
				"nested": map[string]any{
					"level1": map[string]any{
						"level2": "deep value",
						"array":  []any{"a", "b", "c"},
					},
				},
			},
		},

		"should return NotFoundError when order does not exist": {
			id: nonExistentID,
			testOrders: []testOrder{
				{
					id:   orderID,
					name: "Existing Order",
					attributes: map[string]any{
						"category": "standard",
						"price":    99.99,
					},
				},
			},
			setupContext:      func() context.Context { return context.Background() },
			expectedResult:    nil,
			expectedError:     fmt.Sprintf("order with id %s not found", nonExistentID.String()),
			expectNotFoundErr: true,
		},

		"should return error when context is cancelled": {
			id: orderID,
			testOrders: []testOrder{
				{
					id:   orderID,
					name: "Context Test Order",
					attributes: map[string]any{
						"category": "test",
						"price":    49.99,
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

		"should handle multiple orders but return correct attributes": {
			id: orderID,
			testOrders: []testOrder{
				{
					id:   anotherOrderID,
					name: "Other Order",
					attributes: map[string]any{
						"category": "other",
						"price":    199.99,
					},
				},
				{
					id:   orderID,
					name: "Target Order",
					attributes: map[string]any{
						"category":   "target",
						"price":      399.99,
						"priority":   "high",
						"user_id":    "target_user",
						"processing": true,
						"tags":       []string{"express", "priority"},
					},
				},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: map[string]any{
				"category":   "target",
				"price":      399.99,
				"priority":   "high",
				"user_id":    "target_user",
				"processing": true,
				"tags":       []any{"express", "priority"},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			repo := NewOrderRepository(pool)

			// Setup test data
			setupTestOrdersData(t, pool, tc.testOrders)

			// Setup context
			ctx := tc.setupContext()

			// Execute
			result, err := repo.GetOrderAttributesByID(ctx, tc.id)

			// Assert
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, result)

				// Test custom NotFoundError type
				if tc.expectNotFoundErr {
					var notFoundErr *repository.NotFoundError
					assert.True(t, errors.As(err, &notFoundErr))
					assert.Equal(t, OrderResource, notFoundErr.Resource)
					assert.Equal(t, "id", notFoundErr.Key)
					assert.Equal(t, tc.id.String(), notFoundErr.Value)
				}
			} else {
				assert.NoError(t, err)
				assert.EqualValues(t, tc.expectedResult, result)
			}

			// Clean up test data
			cleanupTestOrdersData(t, pool)
		})
	}
}

func setupTestDBForOrders(t *testing.T) *pgxpool.Pool {
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

func setupTestOrdersData(t *testing.T, pool *pgxpool.Pool, orders []testOrder) {
	for _, order := range orders {
		if order.attributes == nil {
			_, err := pool.Exec(
				context.Background(),
				"INSERT INTO orders (id, name) VALUES ($1, $2)",
				order.id, order.name,
			)
			require.NoError(t, err)
			continue
		}

		_, err := pool.Exec(
			context.Background(),
			"INSERT INTO orders (id, name, attributes) VALUES ($1, $2, $3)",
			order.id, order.name, order.attributes,
		)
		require.NoError(t, err)
	}
}

func cleanupTestOrdersData(t *testing.T, pool *pgxpool.Pool) {
	_, err := pool.Exec(context.Background(), "TRUNCATE TABLE orders")
	require.NoError(t, err)
}
