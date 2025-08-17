package advice

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	ro "github.com/CameronXie/access-control-explorer/abac/requestorchestrator"
	"github.com/stretchr/testify/assert"
)

func TestCacheHintAdviceHandler(t *testing.T) {
	tests := map[string]struct {
		headerName         string
		adviceAttributes   map[string]any
		expectedHeaderName string
		expectedHeaderVal  string
		expectError        bool
	}{
		"should set default header with int ttl": {
			headerName: "",
			adviceAttributes: map[string]any{
				"ttl_seconds": 30,
			},
			expectedHeaderName: "X-ABAC-Decision-TTL",
			expectedHeaderVal:  "30",
			expectError:        false,
		},
		"should set custom header with string ttl": {
			headerName: "X-Custom-TTL",
			adviceAttributes: map[string]any{
				"ttl_seconds": "45",
			},
			expectedHeaderName: "X-Custom-TTL",
			expectedHeaderVal:  "45",
			expectError:        false,
		},
		"should error when ttl is missing": {
			headerName:         "",
			adviceAttributes:   map[string]any{},
			expectedHeaderName: "X-ABAC-Decision-TTL",
			expectedHeaderVal:  "",
			expectError:        true,
		},
		"should error when ttl type is invalid": {
			headerName: "",
			adviceAttributes: map[string]any{
				"ttl_seconds": []int{10},
			},
			expectedHeaderName: "X-ABAC-Decision-TTL",
			expectedHeaderVal:  "",
			expectError:        true,
		},
		"should error when ttl is non-positive": {
			headerName: "",
			adviceAttributes: map[string]any{
				"ttl_seconds": 0,
			},
			expectedHeaderName: "X-ABAC-Decision-TTL",
			expectedHeaderVal:  "",
			expectError:        true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := NewCacheHintAdviceHandler(tc.headerName)
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)

			advice := ro.Advice{
				ID:         "cache_hint",
				Attributes: tc.adviceAttributes,
			}

			err := h.Handle(context.Background(), advice, rr, req)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expectedHeaderVal, rr.Header().Get(tc.expectedHeaderName))
		})
	}
}
