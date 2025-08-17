package domain

import "github.com/google/uuid"

// Order represents an order entity with ID, name, and flexible attributes
type Order struct {
	ID         uuid.UUID      `json:"id"`
	Name       string         `json:"name"`
	Attributes map[string]any `json:"attributes"`
}
