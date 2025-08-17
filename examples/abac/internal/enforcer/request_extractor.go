package enforcer

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	ro "github.com/CameronXie/access-control-explorer/abac/requestorchestrator"
	"github.com/CameronXie/access-control-explorer/examples/abac/pkg/trie"
)

// SubjectExtractor extracts subject information from HTTP requests
type SubjectExtractor interface {
	Extract(ctx context.Context, r *http.Request) (*ro.Subject, error)
}

// Operation represents an action and resource pair
type Operation struct {
	Action   ro.Action
	Resource ro.Resource
}

// OperationExtractor extracts operation information from HTTP requests
type OperationExtractor interface {
	Extract(ctx context.Context, r *http.Request) (*Operation, error)
}

// RequestExtractorOption defines configuration options for RequestExtractor
type RequestExtractorOption func(*requestExtractor) error

type requestExtractor struct {
	subjectExtractor       SubjectExtractor
	operationExtractorTrie *trie.Node[map[string]OperationExtractor]
}

// normalizeMethod converts HTTP method to uppercase for consistent lookup
func normalizeMethod(method string) string {
	return strings.ToUpper(method)
}

// parsePathSegments splits URL path into segments, handling root path
func parsePathSegments(path string) []string {
	pathSegments := strings.Split(strings.Trim(path, "/"), "/")
	if len(pathSegments) == 1 && pathSegments[0] == "" {
		return []string{}
	}
	return pathSegments
}

// WithSubjectExtractor sets the subject extractor
func WithSubjectExtractor(extractor SubjectExtractor) RequestExtractorOption {
	return func(re *requestExtractor) error {
		if extractor == nil {
			return fmt.Errorf("subject extractor cannot be nil")
		}
		re.subjectExtractor = extractor
		return nil
	}
}

// WithOperationExtractor registers an OperationExtractor for specific path and method
func WithOperationExtractor(path, method string, extractor OperationExtractor) RequestExtractorOption {
	return func(re *requestExtractor) error {
		if path == "" {
			return fmt.Errorf("path cannot be empty")
		}
		if method == "" {
			return fmt.Errorf("method cannot be empty")
		}
		if extractor == nil {
			return fmt.Errorf("operation extractor cannot be nil")
		}
		return re.registerOperationExtractor(path, method, extractor)
	}
}

// NewRequestExtractor creates a new RequestExtractor instance with options
func NewRequestExtractor(options ...RequestExtractorOption) (RequestExtractor, error) {
	extractor := &requestExtractor{
		operationExtractorTrie: trie.New[map[string]OperationExtractor](),
	}

	// Apply all options
	for _, option := range options {
		if err := option(extractor); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	// Validate required dependencies
	if extractor.subjectExtractor == nil {
		return nil, fmt.Errorf("subject extractor is required")
	}

	return extractor, nil
}

// registerOperationExtractor registers an OperationExtractor for specific path and method
func (re *requestExtractor) registerOperationExtractor(path, method string, extractor OperationExtractor) error {
	pathSegments := parsePathSegments(path)
	normalizedMethod := normalizeMethod(method)

	// Search for existing node
	node, err := re.operationExtractorTrie.Search(pathSegments)
	if err != nil {
		// Path doesn't exist, create it
		methodMap := make(map[string]OperationExtractor)
		methodMap[normalizedMethod] = extractor
		return re.operationExtractorTrie.Insert(pathSegments, methodMap)
	}

	// Path exists
	if _, exists := node.Value[normalizedMethod]; exists {
		return fmt.Errorf("method %s already registered for path %s", method, path)
	}

	node.Value[normalizedMethod] = extractor
	return nil
}

// Extract extracts AccessRequest from HTTP request
func (re *requestExtractor) Extract(ctx context.Context, r *http.Request) (*ro.AccessRequest, error) {
	// Extract subject
	subject, err := re.subjectExtractor.Extract(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("failed to extract subject: %w", err)
	}

	// Extract operation
	operation, err := re.extractOperation(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("failed to extract operation: %w", err)
	}

	return &ro.AccessRequest{
		Subject:  *subject,
		Action:   operation.Action,
		Resource: operation.Resource,
	}, nil
}

// extractOperation extracts operation from HTTP request using registered extractors
func (re *requestExtractor) extractOperation(ctx context.Context, r *http.Request) (*Operation, error) {
	pathSegments := parsePathSegments(r.URL.Path)

	// Find matching extractor in trie
	node, err := re.operationExtractorTrie.Search(pathSegments)
	if err != nil {
		return nil, fmt.Errorf("no operation extractor found for path %s: %w", r.URL.Path, err)
	}

	// Get method-specific extractor
	method := normalizeMethod(r.Method)
	extractor, exists := node.Value[method]
	if !exists {
		return nil, fmt.Errorf("no operation extractor found for method %s on path %s", method, r.URL.Path)
	}

	// Extract operation
	operation, err := extractor.Extract(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("operation extraction failed: %w", err)
	}

	return operation, nil
}
