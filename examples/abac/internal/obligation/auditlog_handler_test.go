package obligation

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	ro "github.com/CameronXie/access-control-explorer/abac/requestorchestrator"
	"github.com/stretchr/testify/assert"
)

type testLogHandler struct {
	messages []string
	levels   []slog.Level
}

func (h *testLogHandler) Handle(_ context.Context, r slog.Record) error { //nolint:gocritic // slog.Handler interface
	h.messages = append(h.messages, r.Message)
	h.levels = append(h.levels, r.Level)
	return nil
}

func (*testLogHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *testLogHandler) WithAttrs(_ []slog.Attr) slog.Handler       { return h }
func (h *testLogHandler) WithGroup(_ string) slog.Handler            { return h }
func (h *testLogHandler) reset()                                     { h.messages = nil; h.levels = nil }

func TestAuditLogHandler_Handle(t *testing.T) {
	testCases := map[string]struct {
		obligation       ro.Obligation
		expectedError    string
		expectedMessage  string
		expectedLogLevel slog.Level
	}{
		"should log message with ERROR level": {
			obligation: ro.Obligation{
				ID: "audit_log",
				Attributes: map[string]any{
					"level":   "ERROR",
					"message": "access denied",
				},
			},
			expectedMessage:  "access denied",
			expectedLogLevel: slog.LevelError,
		},
		"should log message with INFO level when level is invalid": {
			obligation: ro.Obligation{
				ID: "audit_log",
				Attributes: map[string]any{
					"level":   "INVALID",
					"message": "test message",
				},
			},
			expectedMessage:  "test message",
			expectedLogLevel: slog.LevelInfo,
		},
		"should return error when level is missing": {
			obligation: ro.Obligation{
				ID: "audit_log",
				Attributes: map[string]any{
					"message": "test message",
				},
			},
			expectedError: "level is required",
		},
		"should return error when message is missing": {
			obligation: ro.Obligation{
				ID: "audit_log",
				Attributes: map[string]any{
					"level": "ERROR",
				},
			},
			expectedError: "message is required",
		},
		"should return error for invalid attributes type": {
			obligation: ro.Obligation{
				ID: "audit_log",
				Attributes: map[string]any{
					"level":   123,
					"message": 456,
				},
			},
			expectedError: "failed to unmarshal attributes",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Initialize handler and test logger
			testLogger := &testLogHandler{}
			handler := NewAuditLogHandler(slog.New(testLogger))

			// Execute
			err := handler.Handle(
				context.Background(),
				tc.obligation,
				httptest.NewRecorder(),
				httptest.NewRequest(http.MethodGet, "/test", http.NoBody),
			)

			// Assert
			if tc.expectedError != "" {
				assert.ErrorContains(t, err, tc.expectedError)
				assert.Empty(t, testLogger.messages)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedMessage, testLogger.messages[0])
				assert.Equal(t, tc.expectedLogLevel, testLogger.levels[0])
			}

			testLogger.reset()
		})
	}
}
