//nolint:lll // unit test
package enforcer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	ro "github.com/CameronXie/access-control-explorer/abac/requestorchestrator"
)

// Mock implementations
type mockRequestOrchestrator struct {
	mock.Mock
}

func (m *mockRequestOrchestrator) EvaluateAccess(ctx context.Context, req *ro.AccessRequest) (*ro.AccessResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ro.AccessResponse), args.Error(1)
}

type mockRequestExtractor struct {
	mock.Mock
}

func (m *mockRequestExtractor) Extract(ctx context.Context, r *http.Request) (*ro.AccessRequest, error) {
	args := m.Called(ctx, r)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ro.AccessRequest), args.Error(1)
}

type mockObligationHandler struct {
	mock.Mock
}

func (m *mockObligationHandler) Handle(ctx context.Context, obligation ro.Obligation, w http.ResponseWriter, r *http.Request) error {
	args := m.Called(ctx, obligation, w, r)
	return args.Error(0)
}

type mockAdviceHandler struct {
	mock.Mock
}

func (m *mockAdviceHandler) Handle(ctx context.Context, advice ro.Advice, w http.ResponseWriter, r *http.Request) error {
	args := m.Called(ctx, advice, w, r)
	return args.Error(0)
}

// Test logger that captures log messages and levels
type testLogHandler struct {
	messages []string
	levels   []slog.Level
}

func (*testLogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *testLogHandler) Handle(_ context.Context, r slog.Record) error { //nolint:gocritic // slog.Handler interface
	h.messages = append(h.messages, r.Message)
	h.levels = append(h.levels, r.Level)
	return nil
}

func (h *testLogHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	return h
}

func (h *testLogHandler) WithGroup(_ string) slog.Handler {
	return h
}

type expectedLog struct {
	level    slog.Level
	contains string
}

func TestEnforcer_Enforce(t *testing.T) { //nolint:gocyclo // unit test
	// Common helpers to reduce duplication across similar cases
	baseDeleteDocRequest := &ro.AccessRequest{
		Subject:  ro.Subject{ID: "user123", Type: "user"},
		Resource: ro.Resource{ID: "doc456", Type: "document"},
		Action:   ro.Action{ID: "delete"},
	}
	baseReadDocRequest := &ro.AccessRequest{
		Subject:  ro.Subject{ID: "user123", Type: "user"},
		Resource: ro.Resource{ID: "doc456", Type: "document"},
		Action:   ro.Action{ID: "read"},
	}
	newBaseDenyResponse := func() *ro.AccessResponse {
		return &ro.AccessResponse{
			RequestID:   uuid.New(),
			Decision:    ro.Deny,
			Status:      ro.Status{Code: "denied", Message: "Insufficient permissions"},
			EvaluatedAt: time.Now(),
		}
	}
	newBaseNotApplicableResponse := func() *ro.AccessResponse {
		return &ro.AccessResponse{
			RequestID:   uuid.New(),
			Decision:    ro.NotApplicable,
			Status:      ro.Status{Code: "PolicyNotFound", Message: "no applicable policy was found for this request"},
			EvaluatedAt: time.Now(),
		}
	}

	testCases := map[string]struct {
		// Request setup
		httpMethod string
		httpPath   string

		// Mock behaviors
		extractorResult    *ro.AccessRequest
		extractorError     error
		orchestratorResult *ro.AccessResponse
		orchestratorError  error
		obligationHandlers map[string]error // obligationID -> error (nil means success)
		adviceHandlers     map[string]error // adviceID -> error (nil means success)

		// Expected results
		expectedStatus    int
		expectedErrorResp *ErrorResponse // For JSON error responses
		nextCalled        bool
		expectedLogs      []expectedLog
	}{
		"should allow access when decision is permit and obligations succeed": {
			httpMethod:      "GET",
			httpPath:        "/api/documents/123",
			extractorResult: baseReadDocRequest,
			orchestratorResult: &ro.AccessResponse{
				RequestID:   uuid.New(),
				Decision:    ro.Permit,
				Status:      ro.Status{Code: "ok", Message: "Permitted"},
				EvaluatedAt: time.Now(),
				Obligations: []ro.Obligation{
					{ID: "audit", Attributes: map[string]any{"level": "INFO", "message": "ok"}},
				},
				Advices: []ro.Advice{
					{ID: "analytics", Attributes: map[string]any{"track": true}},
				},
			},
			obligationHandlers: map[string]error{
				"audit": nil,
			},
			adviceHandlers: map[string]error{
				"analytics": nil,
			},
			expectedStatus: 200,
			nextCalled:     true,
			expectedLogs: []expectedLog{
				{level: slog.LevelInfo, contains: "access_permitted"},
			},
		},

		"should deny access when decision is deny": {
			httpMethod:         "DELETE",
			httpPath:           "/api/documents/123",
			extractorResult:    baseDeleteDocRequest,
			orchestratorResult: newBaseDenyResponse(),
			expectedStatus:     http.StatusForbidden,
			expectedErrorResp: &ErrorResponse{
				Error:   "access_denied",
				Message: "You do not have permission to access this resource",
			},
			nextCalled: false,
			expectedLogs: []expectedLog{
				{level: slog.LevelInfo, contains: "access_denied"},
			},
		},

		"should log warn when obligation handler fails on deny": {
			httpMethod:      "DELETE",
			httpPath:        "/api/documents/123",
			extractorResult: baseDeleteDocRequest,
			orchestratorResult: func() *ro.AccessResponse {
				resp := newBaseDenyResponse()
				resp.Obligations = []ro.Obligation{
					{ID: "deny-audit", Attributes: map[string]any{"level": "WARN", "message": "deny audit"}},
				}
				return resp
			}(),
			obligationHandlers: map[string]error{
				"deny-audit": errors.New("audit sink unavailable"),
			},
			expectedStatus: http.StatusForbidden,
			expectedErrorResp: &ErrorResponse{
				Error:   "access_denied",
				Message: "You do not have permission to access this resource",
			},
			nextCalled: false,
			expectedLogs: []expectedLog{
				{level: slog.LevelWarn, contains: "obligation_failed_on_deny"},
				{level: slog.LevelInfo, contains: "access_denied"},
			},
		},

		"should log warn when advice handler fails on deny": {
			httpMethod:      "DELETE",
			httpPath:        "/api/documents/123",
			extractorResult: baseDeleteDocRequest,
			orchestratorResult: func() *ro.AccessResponse {
				resp := newBaseDenyResponse()
				resp.Advices = []ro.Advice{
					{ID: "notify-admin", Attributes: map[string]any{"reason": "unauthorized_access"}},
				}
				return resp
			}(),
			adviceHandlers: map[string]error{
				"notify-admin": errors.New("notification service unavailable"),
			},
			expectedStatus: http.StatusForbidden,
			expectedErrorResp: &ErrorResponse{
				Error:   "access_denied",
				Message: "You do not have permission to access this resource",
			},
			nextCalled: false,
			expectedLogs: []expectedLog{
				{level: slog.LevelWarn, contains: "advice_failed_on_deny"},
				{level: slog.LevelInfo, contains: "access_denied"},
			},
		},

		"should return 400 when request extraction fails": {
			httpMethod:     "GET",
			httpPath:       "/api/documents/123",
			extractorError: errors.New("missing required headers"),
			expectedStatus: 400,
			expectedErrorResp: &ErrorResponse{
				Error:   "request_extraction_failed",
				Message: "Invalid access request",
			},
			nextCalled: false,
			expectedLogs: []expectedLog{
				{level: slog.LevelError, contains: "request_extraction_failed"},
			},
		},

		"should return 500 when access evaluation fails": {
			httpMethod:        "GET",
			httpPath:          "/api/documents/123",
			extractorResult:   baseReadDocRequest,
			orchestratorError: errors.New("PDP service unavailable"),
			expectedStatus:    500,
			expectedErrorResp: &ErrorResponse{
				Error:   "access_evaluation_failed",
				Message: "An internal error occurred while evaluating access",
			},
			nextCalled: false,
			expectedLogs: []expectedLog{
				{level: slog.LevelError, contains: "access_evaluation_failed"},
			},
		},

		"should return 500 when obligation handler is not registered": {
			httpMethod:      "GET",
			httpPath:        "/api/documents/123",
			extractorResult: baseReadDocRequest,
			orchestratorResult: &ro.AccessResponse{
				RequestID:   uuid.New(),
				Decision:    ro.Permit,
				Status:      ro.Status{Code: "ok", Message: "Permitted"},
				EvaluatedAt: time.Now(),
				Obligations: []ro.Obligation{
					{ID: "missing-handler", Attributes: map[string]any{"level": "INFO", "message": "x"}},
				},
			},
			obligationHandlers: map[string]error{}, // No handler registered
			expectedStatus:     500,
			expectedErrorResp: &ErrorResponse{
				Error:   "obligation_failed",
				Message: "An internal error occurred while enforcing obligations",
			},
			nextCalled: false,
			expectedLogs: []expectedLog{
				{level: slog.LevelError, contains: "obligation_failed"},
			},
		},

		"should return 500 when obligation handler fails": {
			httpMethod:      "GET",
			httpPath:        "/api/documents/123",
			extractorResult: baseReadDocRequest,
			orchestratorResult: &ro.AccessResponse{
				RequestID:   uuid.New(),
				Decision:    ro.Permit,
				Status:      ro.Status{Code: "ok", Message: "Permitted"},
				EvaluatedAt: time.Now(),
				Obligations: []ro.Obligation{
					{ID: "audit", Attributes: map[string]any{"level": "INFO", "message": "x"}},
				},
			},
			obligationHandlers: map[string]error{
				"audit": errors.New("audit service unavailable"),
			},
			expectedStatus: 500,
			expectedErrorResp: &ErrorResponse{
				Error:   "obligation_failed",
				Message: "An internal error occurred while enforcing obligations",
			},
			nextCalled: false,
			expectedLogs: []expectedLog{
				{level: slog.LevelError, contains: "obligation_failed"},
			},
		},

		"should return 500 when decision is indeterminate": {
			httpMethod:      "GET",
			httpPath:        "/api/documents/123",
			extractorResult: baseReadDocRequest,
			orchestratorResult: &ro.AccessResponse{
				RequestID:   uuid.New(),
				Decision:    ro.Indeterminate,
				Status:      ro.Status{Code: "syntax_error", Message: "Policy syntax error"},
				EvaluatedAt: time.Now(),
			},
			expectedStatus: 500,
			expectedErrorResp: &ErrorResponse{
				Error:   "indeterminate_decision",
				Message: "An internal error occurred while processing the access decision",
			},
			nextCalled: false,
			expectedLogs: []expectedLog{
				{level: slog.LevelError, contains: "access_indeterminate"},
			},
		},

		"should warn when advice handler fails but continue processing": {
			httpMethod:      "GET",
			httpPath:        "/api/documents/123",
			extractorResult: baseReadDocRequest,
			orchestratorResult: &ro.AccessResponse{
				RequestID:   uuid.New(),
				Decision:    ro.Permit,
				Status:      ro.Status{Code: "ok", Message: "Permitted"},
				EvaluatedAt: time.Now(),
				Advices: []ro.Advice{
					{ID: "analytics", Attributes: map[string]any{"track": true}},
				},
			},
			adviceHandlers: map[string]error{
				"analytics": errors.New("analytics service timeout"),
			},
			expectedStatus: 200,
			nextCalled:     true,
			expectedLogs: []expectedLog{
				{level: slog.LevelWarn, contains: "advice_failed"},
				{level: slog.LevelInfo, contains: "access_permitted"},
			},
		},

		"should skip advice when no handler is registered": {
			httpMethod:      "GET",
			httpPath:        "/api/documents/123",
			extractorResult: baseReadDocRequest,
			orchestratorResult: &ro.AccessResponse{
				RequestID:   uuid.New(),
				Decision:    ro.Permit,
				Status:      ro.Status{Code: "ok", Message: "Permitted"},
				EvaluatedAt: time.Now(),
				Advices: []ro.Advice{
					{ID: "unhandled-advice", Attributes: map[string]any{"track": true}},
				},
			},
			adviceHandlers: map[string]error{}, // No handler registered - should be silently skipped
			expectedStatus: 200,
			nextCalled:     true,
			expectedLogs: []expectedLog{
				{level: slog.LevelInfo, contains: "access_permitted"},
			},
		},

		"should handle multiple obligations and advices": {
			httpMethod: "POST",
			httpPath:   "/api/documents",
			extractorResult: &ro.AccessRequest{
				Subject:  ro.Subject{ID: "user123", Type: "user"},
				Resource: ro.Resource{ID: "documents", Type: "collection"},
				Action:   ro.Action{ID: "create"},
			},
			orchestratorResult: &ro.AccessResponse{
				RequestID:   uuid.New(),
				Decision:    ro.Permit,
				Status:      ro.Status{Code: "ok", Message: "Permitted"},
				EvaluatedAt: time.Now(),
				Obligations: []ro.Obligation{
					{ID: "audit", Attributes: map[string]any{"level": "INFO", "message": "created"}},
					{ID: "encryption", Attributes: map[string]any{"algorithm": "AES256"}},
				},
				Advices: []ro.Advice{
					{ID: "analytics", Attributes: map[string]any{"track": true}},
					{ID: "cache-invalidation", Attributes: map[string]any{"keys": []string{"documents"}}},
				},
			},
			obligationHandlers: map[string]error{
				"audit":      nil,
				"encryption": nil,
			},
			adviceHandlers: map[string]error{
				"analytics":          nil,
				"cache-invalidation": nil,
			},
			expectedStatus: 200,
			nextCalled:     true,
			expectedLogs: []expectedLog{
				{level: slog.LevelInfo, contains: "access_permitted"},
			},
		},

		"should return 403 when decision is not applicable and log info": {
			httpMethod: "GET",
			httpPath:   "/api/unknown",
			extractorResult: &ro.AccessRequest{
				Subject:  ro.Subject{ID: "user123", Type: "user"},
				Resource: ro.Resource{ID: "unknown", Type: "unknown"},
				Action:   ro.Action{ID: "read"},
			},
			orchestratorResult: newBaseNotApplicableResponse(),
			expectedStatus:     http.StatusForbidden,
			expectedErrorResp: &ErrorResponse{
				Error:   "access_denied",
				Message: "You do not have permission to access this resource",
			},
			nextCalled: false,
			expectedLogs: []expectedLog{
				{level: slog.LevelInfo, contains: "access_not_applicable"},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Initialize mocks in test loop
			orchestrator := &mockRequestOrchestrator{}
			extractor := &mockRequestExtractor{}
			obligationHandlers := make(map[string]*mockObligationHandler)
			adviceHandlers := make(map[string]*mockAdviceHandler)

			// Setup extractor mock
			extractor.On("Extract", mock.Anything, mock.Anything).Return(tc.extractorResult, tc.extractorError)

			// Setup orchestrator mock
			if tc.extractorResult != nil {
				orchestrator.On("EvaluateAccess", mock.Anything, tc.extractorResult).Return(tc.orchestratorResult, tc.orchestratorError)
			}

			// Setup obligation handler mocks
			if tc.orchestratorResult != nil {
				for obligationID, expectedError := range tc.obligationHandlers {
					handler := &mockObligationHandler{}
					for _, obligation := range tc.orchestratorResult.Obligations {
						if obligation.ID == obligationID {
							handler.On("Handle", mock.Anything, obligation, mock.Anything, mock.Anything).Return(expectedError)
							break
						}
					}
					obligationHandlers[obligationID] = handler
				}
			}

			// Setup advice handler mocks
			if tc.orchestratorResult != nil {
				for adviceID, expectedError := range tc.adviceHandlers {
					handler := &mockAdviceHandler{}
					for _, advice := range tc.orchestratorResult.Advices {
						if advice.ID == adviceID {
							handler.On("Handle", mock.Anything, advice, mock.Anything, mock.Anything).Return(expectedError)
							break
						}
					}
					adviceHandlers[adviceID] = handler
				}
			}

			// Create test logger
			logHandler := &testLogHandler{}
			logger := slog.New(logHandler)

			// Create enforcer options
			options := make([]Option, 0)
			for obligationID, handler := range obligationHandlers {
				options = append(options, WithObligationHandler(obligationID, handler))
			}
			for adviceID, handler := range adviceHandlers {
				options = append(options, WithAdviceHandler(adviceID, handler))
			}

			// Initialize enforcer in test loop
			enforcer := NewEnforcer(orchestrator, extractor, logger, options...)

			// Setup next handler to track if it was called
			nextCalled := false
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			// Create test request and response recorder
			req := httptest.NewRequest(tc.httpMethod, tc.httpPath, http.NoBody)
			req.RemoteAddr = "192.168.1.1:8080"
			recorder := httptest.NewRecorder()

			// Execute
			middleware := enforcer.Enforce(nextHandler)
			middleware.ServeHTTP(recorder, req)

			// Assert HTTP response status
			assert.Equal(t, tc.expectedStatus, recorder.Code)

			// Assert response body for error cases
			if tc.expectedErrorResp != nil {
				assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
				var actualErrorResp ErrorResponse
				err := json.Unmarshal(recorder.Body.Bytes(), &actualErrorResp)
				assert.NoError(t, err, "Response should be valid JSON")
				assert.Equal(t, *tc.expectedErrorResp, actualErrorResp)
			}

			// Assert next handler was called appropriately
			assert.Equal(t, tc.nextCalled, nextCalled)

			// Assert logs: check both message content and level
			for _, expected := range tc.expectedLogs {
				found := false
				for i, msg := range logHandler.messages {
					if strings.Contains(msg, expected.contains) && logHandler.levels[i] == expected.level {
						found = true
						break
					}
				}
				assert.True(t, found, fmt.Sprintf("Expected log with level %v containing '%s' not found. Actual: %v", expected.level, expected.contains, logHandler.messages))
			}

			// Verify all mocks were called as expected
			orchestrator.AssertExpectations(t)
			extractor.AssertExpectations(t)
			for _, handler := range obligationHandlers {
				handler.AssertExpectations(t)
			}
			for _, handler := range adviceHandlers {
				handler.AssertExpectations(t)
			}
		})
	}
}

func TestEnforcer_WithCustomErrorHandler(t *testing.T) {
	// Test that custom error handler is used correctly
	orchestrator := &mockRequestOrchestrator{}
	extractor := &mockRequestExtractor{}

	// Setup mocks to trigger an error
	extractor.On("Extract", mock.Anything, mock.Anything).Return(nil, errors.New("test error"))

	// Custom error handler that adds extra field
	customErrorHandler := func(w http.ResponseWriter, _ *http.Request, statusCode int, errorResp ErrorResponse) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom-Header", "test-value")
		w.WriteHeader(statusCode)

		// Add timestamp to error response
		response := map[string]any{
			"error":     errorResp.Error,
			"message":   errorResp.Message,
			"timestamp": "2024-01-01T00:00:00Z", // Fixed for testing
		}
		assert.NoError(t, json.NewEncoder(w).Encode(response))
	}

	logHandler := &testLogHandler{}
	logger := slog.New(logHandler)

	// Create enforcer with custom error handler
	enforcer := NewEnforcer(orchestrator, extractor, logger, WithErrorHandler(customErrorHandler))

	// Create test request
	req := httptest.NewRequest("GET", "/test", http.NoBody)
	recorder := httptest.NewRecorder()

	// Execute
	nextHandler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("Next handler should not be called")
	})
	middleware := enforcer.Enforce(nextHandler)
	middleware.ServeHTTP(recorder, req)

	// Assert custom error handler was used
	assert.Equal(t, 400, recorder.Code)
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	assert.Equal(t, "test-value", recorder.Header().Get("X-Custom-Header"))

	// Assert custom response format
	var response map[string]any
	err := json.Unmarshal(recorder.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "request_extraction_failed", response["error"])
	assert.Equal(t, "Invalid access request", response["message"])
	assert.Equal(t, "2024-01-01T00:00:00Z", response["timestamp"])
}
