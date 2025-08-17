package enforcer

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	ro "github.com/CameronXie/access-control-explorer/abac/requestorchestrator"
	"github.com/CameronXie/access-control-explorer/examples/abac/pkg/trie"
)

// Mock implementations
type mockSubjectExtractor struct {
	mock.Mock
}

func (m *mockSubjectExtractor) Extract(ctx context.Context, r *http.Request) (*ro.Subject, error) {
	args := m.Called(ctx, r)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ro.Subject), args.Error(1)
}

type mockOperationExtractor struct {
	mock.Mock
}

func (m *mockOperationExtractor) Extract(ctx context.Context, r *http.Request) (*Operation, error) {
	args := m.Called(ctx, r)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Operation), args.Error(1)
}

func TestNewRequestExtractor(t *testing.T) {
	testCases := map[string]struct {
		options       []RequestExtractorOption
		expectedError string
	}{
		"should fail when no subject extractor provided": {
			options:       []RequestExtractorOption{},
			expectedError: "subject extractor is required",
		},

		"should succeed with valid subject extractor": {
			options: []RequestExtractorOption{
				WithSubjectExtractor(&mockSubjectExtractor{}),
			},
		},

		"should succeed with subject and operation extractors": {
			options: []RequestExtractorOption{
				WithSubjectExtractor(&mockSubjectExtractor{}),
				WithOperationExtractor("/users", "GET", &mockOperationExtractor{}),
			},
		},

		"should fail when empty path provided": {
			options: []RequestExtractorOption{
				WithSubjectExtractor(&mockSubjectExtractor{}),
				WithOperationExtractor("", "GET", &mockOperationExtractor{}),
			},
			expectedError: "path cannot be empty",
		},

		"should fail when empty method provided": {
			options: []RequestExtractorOption{
				WithSubjectExtractor(&mockSubjectExtractor{}),
				WithOperationExtractor("/users", "", &mockOperationExtractor{}),
			},
			expectedError: "method cannot be empty",
		},

		"should fail when nil operation extractor provided": {
			options: []RequestExtractorOption{
				WithSubjectExtractor(&mockSubjectExtractor{}),
				WithOperationExtractor("/users", "GET", nil),
			},
			expectedError: "operation extractor cannot be nil",
		},

		"should fail when duplicate path and method registered": {
			options: []RequestExtractorOption{
				WithSubjectExtractor(&mockSubjectExtractor{}),
				WithOperationExtractor("/users", "GET", &mockOperationExtractor{}),
				WithOperationExtractor("/users", "GET", &mockOperationExtractor{}),
			},
			expectedError: "method GET already registered for path /users",
		},

		"should succeed with multiple different paths": {
			options: []RequestExtractorOption{
				WithSubjectExtractor(&mockSubjectExtractor{}),
				WithOperationExtractor("/users", "GET", &mockOperationExtractor{}),
				WithOperationExtractor("/users", "POST", &mockOperationExtractor{}),
				WithOperationExtractor("/admin", "DELETE", &mockOperationExtractor{}),
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			extractor, err := NewRequestExtractor(tc.options...)

			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, extractor)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, extractor)
			}
		})
	}
}

func TestRequestExtractor_Extract(t *testing.T) {
	testCases := map[string]struct {
		subject                *ro.Subject
		subjectError           error
		opExtractorPath        string
		opExtractorMethod      string
		operation              *Operation
		operationError         error
		shouldExtractOperation bool
		request                *http.Request
		expectedResult         *ro.AccessRequest
		expectedError          string
	}{
		"should successfully extract access request": {
			subject: &ro.Subject{
				ID:   "user123",
				Type: "users",
			},
			operation: &Operation{
				Action:   ro.Action{ID: "read"},
				Resource: ro.Resource{Type: "documents"},
			},
			opExtractorPath:        "/documents",
			opExtractorMethod:      http.MethodGet,
			shouldExtractOperation: true,
			request:                createTestRequest("GET", "/documents"),
			expectedResult: &ro.AccessRequest{
				Subject: ro.Subject{
					ID:   "user123",
					Type: "users",
				},
				Action:   ro.Action{ID: "read"},
				Resource: ro.Resource{Type: "documents"},
			},
		},

		"should fail when subject extraction fails": {
			subjectError: errors.New("subject extraction failed"),
			operation: &Operation{
				Action:   ro.Action{ID: "read"},
				Resource: ro.Resource{Type: "documents"},
			},
			opExtractorPath:   "/documents",
			opExtractorMethod: http.MethodGet,
			request:           createTestRequest("GET", "/documents"),
			expectedError:     "failed to extract subject",
		},

		"should fail when operation extraction fails": {
			subject: &ro.Subject{
				ID:   "user123",
				Type: "users",
			},
			operationError:         errors.New("operation extraction failed"),
			opExtractorPath:        "/documents",
			opExtractorMethod:      http.MethodGet,
			shouldExtractOperation: true,
			request:                createTestRequest("GET", "/documents"),
			expectedError:          "failed to extract operation",
		},

		"should fail when no operation extractor found for path": {
			subject: &ro.Subject{
				ID:   "user123",
				Type: "users",
			},
			operation: &Operation{
				Action:   ro.Action{ID: "read"},
				Resource: ro.Resource{Type: "documents"},
			},
			opExtractorPath:   "/documents",
			opExtractorMethod: http.MethodGet,
			request:           createTestRequest("GET", "/unknown"),
			expectedError:     "no operation extractor found for path /unknown",
		},

		"should fail when no operation extractor found for method": {
			subject: &ro.Subject{
				ID:   "user123",
				Type: "users",
			},
			operation: &Operation{
				Action:   ro.Action{ID: "read"},
				Resource: ro.Resource{Type: "documents"},
			},
			opExtractorPath:   "/documents",
			opExtractorMethod: http.MethodGet,
			request:           createTestRequest(http.MethodPost, "/documents"),
			expectedError:     "no operation extractor found for method POST on path /documents",
		},

		"should handle complex paths with parameters": {
			subject: &ro.Subject{
				ID:   "user123",
				Type: "users",
			},
			operation: &Operation{
				Action:   ro.Action{ID: "read"},
				Resource: ro.Resource{ID: "document123", Type: "documents"},
			},
			opExtractorPath:        "/documents/*",
			opExtractorMethod:      http.MethodGet,
			shouldExtractOperation: true,
			request:                createTestRequest("GET", "/documents/document123"),
			expectedResult: &ro.AccessRequest{
				Subject: ro.Subject{
					ID:   "user123",
					Type: "users",
				},
				Action: ro.Action{ID: "read"},
				Resource: ro.Resource{
					ID:   "document123",
					Type: "documents",
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Setup mocks
			subjectExtractor := &mockSubjectExtractor{}
			subjectExtractor.On("Extract", mock.Anything, tc.request).Return(tc.subject, tc.subjectError)

			opExtractor := &mockOperationExtractor{}

			if tc.shouldExtractOperation {
				opExtractor.On("Extract", mock.Anything, tc.request).Return(tc.operation, tc.operationError)
			}

			extractor, err := NewRequestExtractor(
				WithSubjectExtractor(subjectExtractor),
				WithOperationExtractor(tc.opExtractorPath, tc.opExtractorMethod, opExtractor),
			)
			require.NoError(t, err)

			// Execute
			result, err := extractor.Extract(context.Background(), tc.request)

			// Assert
			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
			}

			// Verify mocks
			subjectExtractor.AssertExpectations(t)
			opExtractor.AssertExpectations(t)
		})
	}
}

func TestWithSubjectExtractor(t *testing.T) {
	testCases := map[string]struct {
		extractor     SubjectExtractor
		expectedError string
	}{
		"should succeed with valid extractor": {
			extractor: &mockSubjectExtractor{},
		},
		"should fail with nil extractor": {
			extractor:     nil,
			expectedError: "subject extractor cannot be nil",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			re := &requestExtractor{}
			option := WithSubjectExtractor(tc.extractor)
			err := option(re)

			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.extractor, re.subjectExtractor)
			}
		})
	}
}

func TestWithOperationExtractor(t *testing.T) {
	testCases := map[string]struct {
		path          string
		method        string
		extractor     OperationExtractor
		expectedError string
	}{
		"should succeed with valid parameters": {
			path:      "/users",
			method:    "GET",
			extractor: &mockOperationExtractor{},
		},

		"should fail with empty path": {
			path:          "",
			method:        "GET",
			extractor:     &mockOperationExtractor{},
			expectedError: "path cannot be empty",
		},

		"should succeed with root path": {
			path:      "/",
			method:    "GET",
			extractor: &mockOperationExtractor{},
		},

		"should fail with empty method": {
			path:          "/users",
			method:        "",
			extractor:     &mockOperationExtractor{},
			expectedError: "method cannot be empty",
		},

		"should fail with nil extractor": {
			path:          "/users",
			method:        "GET",
			extractor:     nil,
			expectedError: "operation extractor cannot be nil",
		},

		"should succeed with wildcard path": {
			path:      "/users/*/profile",
			method:    "GET",
			extractor: &mockOperationExtractor{},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			re := &requestExtractor{
				operationExtractorTrie: trie.New[map[string]OperationExtractor](),
			}
			option := WithOperationExtractor(tc.path, tc.method, tc.extractor)
			err := option(re)

			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
				return
			}

			assert.NoError(t, err)
			n, err := re.operationExtractorTrie.Search(parsePathSegments(tc.path))
			assert.NoError(t, err)
			assert.Equal(t, tc.extractor, n.Value[tc.method])
		})
	}
}

func TestNormalizeMethod(t *testing.T) {
	testCases := map[string]struct {
		method   string
		expected string
	}{
		"should normalize lowercase": {
			method:   "get",
			expected: "GET",
		},
		"should normalize mixed case": {
			method:   "PoSt",
			expected: "POST",
		},
		"should keep uppercase": {
			method:   "DELETE",
			expected: "DELETE",
		},
		"should handle empty string": {
			method:   "",
			expected: "",
		},
		"should handle special methods": {
			method:   "patch",
			expected: "PATCH",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			result := normalizeMethod(tc.method)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Helper function to create HTTP requests
func createTestRequest(method, path string) *http.Request {
	req := &http.Request{
		Method: method,
		URL: &url.URL{
			Path: path,
		},
	}
	return req
}
