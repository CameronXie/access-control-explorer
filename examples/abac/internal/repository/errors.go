package repository

import (
	"fmt"
)

// NotFoundError represents an error when a resource is not found
type NotFoundError struct {
	Resource string
	Key      string
	Value    string
}

// Error implements the error interface
func (e *NotFoundError) Error() string {
	return fmt.Sprintf("%s with %s %s not found", e.Resource, e.Key, e.Value)
}
