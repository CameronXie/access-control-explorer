package operations

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	ro "github.com/CameronXie/access-control-explorer/abac/requestorchestrator"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/enforcer"
	ip "github.com/CameronXie/access-control-explorer/examples/abac/internal/infoprovider"
)

const (
	ActionRead   = "read"
	ActionCreate = "create"
)

// IDExtractor extracts resource ID from HTTP request
type IDExtractor func(r *http.Request) (string, error)

// OrderExtractorOption configures order extractor behavior
type OrderExtractorOption func(*orderExtractor) error

type orderExtractor struct {
	action      string
	idExtractor IDExtractor
}

// WithIDExtractor configures ID extraction for resource-specific operations
func WithIDExtractor(extractor IDExtractor) OrderExtractorOption {
	return func(e *orderExtractor) error {
		e.idExtractor = extractor
		return nil
	}
}

// NewOrderExtractor creates an order operation extractor
func NewOrderExtractor(action string, options ...OrderExtractorOption) (enforcer.OperationExtractor, error) {
	e := &orderExtractor{
		action: action,
	}

	for _, option := range options {
		if err := option(e); err != nil {
			return nil, fmt.Errorf("failed to configure order extractor: %w", err)
		}
	}

	return e, nil
}

// Extract extracts operation details from HTTP request
func (e *orderExtractor) Extract(_ context.Context, r *http.Request) (*enforcer.Operation, error) {
	operation := &enforcer.Operation{
		Action:   ro.Action{ID: e.action},
		Resource: ro.Resource{Type: string(ip.InfoTypeOrder)},
	}

	// Skip ID extraction for operations that don't need it (e.g., create, list)
	if e.idExtractor == nil {
		return operation, nil
	}

	id, err := e.idExtractor(r)
	if err != nil {
		return nil, fmt.Errorf("failed to extract order ID: %w", err)
	}

	operation.Resource.ID = id
	return operation, nil
}

// ExtractOrderIDFromPath extracts order ID from URL path /orders/{id}
func ExtractOrderIDFromPath(r *http.Request) (string, error) {
	pattern := regexp.MustCompile(`^/orders/([a-fA-F0-9-]{36})$`)
	matches := pattern.FindStringSubmatch(r.URL.Path)

	if len(matches) < 2 {
		return "", fmt.Errorf("path %q does not match /orders/{id} pattern", r.URL.Path)
	}

	return matches[1], nil
}
