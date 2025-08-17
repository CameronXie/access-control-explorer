package jwt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	ro "github.com/CameronXie/access-control-explorer/abac/requestorchestrator"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/api/rest/middleware"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/infoprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testContextKey string

func TestSubjectExtractor_Extract(t *testing.T) {
	testCases := map[string]struct {
		setupContext    func() context.Context
		setupRequest    func(ctx context.Context) *http.Request
		expectedSubject *ro.Subject
		expectedError   string
	}{
		"should extract subject successfully when user ID exists in context": {
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), middleware.UserIDContextKey, "user123")
			},
			setupRequest: func(ctx context.Context) *http.Request {
				return httptest.NewRequest("GET", "/test", http.NoBody).WithContext(ctx)
			},
			expectedSubject: &ro.Subject{
				ID:   "user123",
				Type: string(infoprovider.InfoTypeUser),
			},
		},

		"should return error when user ID is not found in context": {
			setupContext: func() context.Context {
				return context.Background()
			},
			setupRequest: func(ctx context.Context) *http.Request {
				return httptest.NewRequest("GET", "/test", http.NoBody).WithContext(ctx)
			},
			expectedError: "user ID not found in context",
		},

		"should return error when user ID has wrong type in context": {
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), middleware.UserIDContextKey, 123)
			},
			setupRequest: func(ctx context.Context) *http.Request {
				return httptest.NewRequest("GET", "/test", http.NoBody).WithContext(ctx)
			},
			expectedError: "user ID not found in context",
		},

		"should return error when context has different key": {
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), testContextKey("different_key"), "user123")
			},
			setupRequest: func(ctx context.Context) *http.Request {
				return httptest.NewRequest("GET", "/test", http.NoBody).WithContext(ctx)
			},
			expectedError: "user ID not found in context",
		},

		"should extract subject with empty user ID if that exists in context": {
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), middleware.UserIDContextKey, "")
			},
			setupRequest: func(ctx context.Context) *http.Request {
				return httptest.NewRequest("GET", "/test", http.NoBody).WithContext(ctx)
			},
			expectedSubject: &ro.Subject{
				ID:   "",
				Type: string(infoprovider.InfoTypeUser),
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			extractor := NewSubjectExtractor()
			ctx := tc.setupContext()
			req := tc.setupRequest(ctx)

			result, err := extractor.Extract(context.Background(), req)

			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tc.expectedSubject.ID, result.ID)
				assert.Equal(t, tc.expectedSubject.Type, result.Type)
			}
		})
	}
}

func TestSubjectExtractor_ExtractContextParameter(t *testing.T) {
	testCases := map[string]struct {
		contextParam    context.Context
		setupRequest    func() *http.Request
		expectedSubject *ro.Subject
		expectedError   string
	}{
		"should ignore context parameter and use request context instead": {
			contextParam: context.WithValue(context.Background(), middleware.UserIDContextKey, "wrong-user"),
			setupRequest: func() *http.Request {
				ctx := context.WithValue(context.Background(), middleware.UserIDContextKey, "correct-user")
				return httptest.NewRequest("GET", "/test", http.NoBody).WithContext(ctx)
			},
			expectedSubject: &ro.Subject{
				ID:   "correct-user",
				Type: string(infoprovider.InfoTypeUser),
			},
		},

		"should use request context even when context parameter is nil": {
			contextParam: nil,
			setupRequest: func() *http.Request {
				ctx := context.WithValue(context.Background(), middleware.UserIDContextKey, "user456")
				return httptest.NewRequest("GET", "/test", http.NoBody).WithContext(ctx)
			},
			expectedSubject: &ro.Subject{
				ID:   "user456",
				Type: string(infoprovider.InfoTypeUser),
			},
		},

		"should return error when both contexts have no user ID": {
			contextParam: context.Background(),
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/test", http.NoBody)
			},
			expectedError: "user ID not found in context",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			extractor := NewSubjectExtractor()
			req := tc.setupRequest()

			result, err := extractor.Extract(tc.contextParam, req)

			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tc.expectedSubject.ID, result.ID)
				assert.Equal(t, tc.expectedSubject.Type, result.Type)
			}
		})
	}
}
