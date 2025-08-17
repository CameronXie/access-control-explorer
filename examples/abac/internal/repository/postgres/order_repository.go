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

	"github.com/CameronXie/access-control-explorer/examples/abac/internal/domain"
)

const (
	OrderResource = "order"
)

// OrderRepository provides database operations for orders
type OrderRepository struct {
	pool *pgxpool.Pool
}

// NewOrderRepository creates a new OrderRepository instance
func NewOrderRepository(pool *pgxpool.Pool) *OrderRepository {
	return &OrderRepository{
		pool: pool,
	}
}

// CreateOrder creates a new order in the database
func (r *OrderRepository) CreateOrder(ctx context.Context, order *domain.Order) error {
	query := "INSERT INTO orders (id, name, attributes) VALUES ($1, $2, $3)"

	_, err := r.pool.Exec(ctx, query, order.ID, order.Name, order.Attributes)
	if err != nil {
		return fmt.Errorf("failed to create order: %w", err)
	}

	return nil
}

// GetOrderByID retrieves an order by its ID from the database
func (r *OrderRepository) GetOrderByID(ctx context.Context, id uuid.UUID) (*domain.Order, error) {
	var order domain.Order
	query := "SELECT id, name, attributes FROM orders WHERE id = $1"

	err := r.pool.QueryRow(ctx, query, id).Scan(&order.ID, &order.Name, &order.Attributes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &repository.NotFoundError{
				Resource: OrderResource,
				Key:      "id",
				Value:    id.String(),
			}
		}
		return nil, fmt.Errorf("failed to retrieve order with id %s: %w", id, err)
	}

	return &order, nil
}

// GetOrderAttributesByID retrieves order attributes by order ID.
// Returns the attributes as a map for use by info providers.
func (r *OrderRepository) GetOrderAttributesByID(ctx context.Context, id uuid.UUID) (map[string]any, error) {
	var attributesData []byte
	query := "SELECT attributes FROM orders WHERE id = $1"

	err := r.pool.QueryRow(ctx, query, id).Scan(&attributesData)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &repository.NotFoundError{
				Resource: OrderResource,
				Key:      "id",
				Value:    id.String(),
			}
		}
		return nil, fmt.Errorf("query attributes for order %s: %w", id, err)
	}

	// Decode JSON attributes
	attrs := make(map[string]any)
	if len(attributesData) > 0 {
		if err := json.Unmarshal(attributesData, &attrs); err != nil {
			return nil, fmt.Errorf("decode attributes for order %s: %w", id, err)
		}
	}

	return attrs, nil
}
