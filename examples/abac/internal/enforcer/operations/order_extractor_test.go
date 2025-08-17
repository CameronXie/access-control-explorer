package operations

import (
	"context"
	"net/http"
	"testing"

	ip "github.com/CameronXie/access-control-explorer/examples/abac/internal/infoprovider"
	"github.com/stretchr/testify/assert"

	ro "github.com/CameronXie/access-control-explorer/abac/requestorchestrator"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/enforcer"
)

func TestNewOrderExtractor(t *testing.T) {
	testCases := map[string]struct {
		action         string
		options        []OrderExtractorOption
		expectedAction string
		hasIDExtractor bool
		expectedError  string
	}{
		"should create extractor with action only": {
			action:         ActionCreate,
			options:        nil,
			expectedAction: ActionCreate,
			hasIDExtractor: false,
		},
		"should create extractor with action and ID extractor": {
			action: ActionRead,
			options: []OrderExtractorOption{
				WithIDExtractor(ExtractOrderIDFromPath),
			},
			expectedAction: ActionRead,
			hasIDExtractor: true,
		},
		"should handle multiple options": {
			action: ActionRead,
			options: []OrderExtractorOption{
				WithIDExtractor(ExtractOrderIDFromPath),
				WithIDExtractor(func(*http.Request) (string, error) {
					return "test", nil
				}),
			},
			expectedAction: ActionRead,
			hasIDExtractor: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			extractor, err := NewOrderExtractor(tc.action, tc.options...)

			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, extractor)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, extractor)

			// Verify internal state
			orderExt := extractor.(*orderExtractor)
			assert.Equal(t, tc.expectedAction, orderExt.action)
			assert.Equal(t, tc.hasIDExtractor, orderExt.idExtractor != nil)
		})
	}
}

func TestOrderExtractor_Extract(t *testing.T) {
	customExtractor := func(*http.Request) (string, error) {
		return "custom-id", nil
	}

	customErrExtractor := func(*http.Request) (string, error) {
		return "", assert.AnError
	}

	testCases := map[string]struct {
		action        string
		options       []OrderExtractorOption
		requestPath   string
		expectedOp    *enforcer.Operation
		expectedError string
	}{
		"should extract operation without ID for create action": {
			action:      ActionCreate,
			requestPath: "/orders",
			expectedOp: &enforcer.Operation{
				Action:   ro.Action{ID: ActionCreate},
				Resource: ro.Resource{Type: string(ip.InfoTypeOrder)},
			},
		},

		"should extract operation with UUID ID": {
			action:      ActionRead,
			options:     []OrderExtractorOption{WithIDExtractor(ExtractOrderIDFromPath)},
			requestPath: "/orders/6ba7b812-9dad-11d1-80b4-00c04fd430c8",
			expectedOp: &enforcer.Operation{
				Action:   ro.Action{ID: ActionRead},
				Resource: ro.Resource{Type: string(ip.InfoTypeOrder), ID: "6ba7b812-9dad-11d1-80b4-00c04fd430c8"},
			},
		},

		"should handle ID extraction error": {
			action:        ActionRead,
			options:       []OrderExtractorOption{WithIDExtractor(ExtractOrderIDFromPath)},
			requestPath:   "/orders/invalid-path/extra",
			expectedError: "failed to extract order ID",
		},

		"should handle custom ID extractor success": {
			action:      ActionRead,
			options:     []OrderExtractorOption{WithIDExtractor(customExtractor)},
			requestPath: "/any/path",
			expectedOp: &enforcer.Operation{
				Action:   ro.Action{ID: ActionRead},
				Resource: ro.Resource{Type: string(ip.InfoTypeOrder), ID: "custom-id"},
			},
		},

		"should handle custom ID extractor error": {
			action:        ActionRead,
			options:       []OrderExtractorOption{WithIDExtractor(customErrExtractor)},
			requestPath:   "/any/path",
			expectedError: "failed to extract order ID",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Set up
			extractor, err := NewOrderExtractor(tc.action, tc.options...)
			assert.NoError(t, err)

			// Construct request from path
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tc.requestPath, http.NoBody)
			assert.NoError(t, err)

			ctx := context.Background()

			// Execute
			operation, err := extractor.Extract(ctx, req)

			// Assert
			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, operation)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedOp, operation)
		})
	}
}

func TestExtractOrderIDFromPath(t *testing.T) {
	testCases := map[string]struct {
		requestPath   string
		expectedID    string
		expectedError string
	}{
		"should extract UUID from valid path": {
			requestPath: "/orders/6ba7b812-9dad-11d1-80b4-00c04fd430c8",
			expectedID:  "6ba7b812-9dad-11d1-80b4-00c04fd430c8",
		},
		"should extract UUID with uppercase letters": {
			requestPath: "/orders/6BA7B812-9DAD-11D1-80B4-00C04FD430C8",
			expectedID:  "6BA7B812-9DAD-11D1-80B4-00C04FD430C8",
		},
		"should extract UUID with mixed case": {
			requestPath: "/orders/6ba7b812-9dad-11D1-80b4-00c04fd430c8",
			expectedID:  "6ba7b812-9dad-11D1-80b4-00c04fd430c8",
		},
		"should fail with numeric ID": {
			requestPath:   "/orders/123",
			expectedError: "does not match /orders/{id} pattern",
		},
		"should fail with invalid path format": {
			requestPath:   "/orders",
			expectedError: "does not match /orders/{id} pattern",
		},
		"should fail with extra path segments": {
			requestPath:   "/orders/6ba7b812-9dad-11d1-80b4-00c04fd430c8/extra",
			expectedError: "does not match /orders/{id} pattern",
		},
		"should fail with wrong resource path": {
			requestPath:   "/users/6ba7b812-9dad-11d1-80b4-00c04fd430c8",
			expectedError: "does not match /orders/{id} pattern",
		},
		"should fail with invalid UUID format - too short": {
			requestPath:   "/orders/6ba7b812-9dad-11d1-80b4-00c04fd430c",
			expectedError: "does not match /orders/{id} pattern",
		},
		"should fail with invalid UUID format - too long": {
			requestPath:   "/orders/6ba7b812-9dad-11d1-80b4-00c04fd430c80",
			expectedError: "does not match /orders/{id} pattern",
		},
		"should fail with invalid UUID format - missing hyphens": {
			requestPath:   "/orders/6ba7b8129dad11D180b400c04fd430c8",
			expectedError: "does not match /orders/{id} pattern",
		},
		"should fail with invalid UUID format - wrong hyphen positions": {
			requestPath:   "/orders/550e84-00e29b-41d4a716-446655440000",
			expectedError: "does not match /orders/{id} pattern",
		},
		"should fail with empty ID": {
			requestPath:   "/orders/",
			expectedError: "does not match /orders/{id} pattern",
		},
		"should fail with special characters in UUID": {
			requestPath:   "/orders/6ba7b812-9dad-11d1-80b4-00c04fd430c@",
			expectedError: "does not match /orders/{id} pattern",
		},
		"should fail with spaces in UUID": {
			requestPath:   "/orders/6ba7b812-9dad-11d1-80b4-00c04fd43 000",
			expectedError: "does not match /orders/{id} pattern",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Construct request from path
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tc.requestPath, http.NoBody)
			assert.NoError(t, err)

			// Execute
			id, err := ExtractOrderIDFromPath(req)

			// Assert
			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Empty(t, id)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedID, id)
		})
	}
}

func TestWithIDExtractor(t *testing.T) {
	testCases := map[string]struct {
		extractor     IDExtractor
		expectedError string
	}{
		"should configure ID extractor successfully": {
			extractor: ExtractOrderIDFromPath,
		},
		"should configure custom ID extractor successfully": {
			extractor: func(*http.Request) (string, error) {
				return "test-id", nil
			},
		},
		"should configure nil extractor successfully": {
			extractor: nil,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			option := WithIDExtractor(tc.extractor)
			assert.NotNil(t, option)

			// Test that option can be applied
			extractor := &orderExtractor{}
			err := option(extractor)

			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
				return
			}

			assert.NoError(t, err)
			if tc.extractor != nil {
				assert.NotNil(t, extractor.idExtractor)
			} else {
				assert.Nil(t, extractor.idExtractor)
			}
		})
	}
}
