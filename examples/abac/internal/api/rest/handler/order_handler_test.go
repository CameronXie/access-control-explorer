package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CameronXie/access-control-explorer/examples/abac/internal/api/rest/middleware"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/domain"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/repository"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockOrderRepository struct {
	mock.Mock
}

func (m *mockOrderRepository) CreateOrder(ctx context.Context, order *domain.Order) error {
	args := m.Called(ctx, order)
	return args.Error(0)
}

func (m *mockOrderRepository) GetOrderByID(ctx context.Context, id uuid.UUID) (*domain.Order, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Order), args.Error(1)
}

// testLogger captures log messages and levels for testing
type testLogger struct {
	messages []string
	levels   []slog.Level
	buffer   *bytes.Buffer
}

func newTestLogger() *testLogger {
	buffer := &bytes.Buffer{}
	return &testLogger{
		messages: make([]string, 0),
		levels:   make([]slog.Level, 0),
		buffer:   buffer,
	}
}

func (tl *testLogger) getLogger() *slog.Logger {
	handler := slog.NewTextHandler(tl.buffer, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})

	// Create a custom handler that captures messages and levels
	return slog.New(&captureHandler{
		testLogger: tl,
		handler:    handler,
	})
}

func (tl *testLogger) reset() {
	tl.messages = tl.messages[:0]
	tl.levels = tl.levels[:0]
	tl.buffer.Reset()
}

// captureHandler wraps the original handler to capture log data
type captureHandler struct {
	testLogger *testLogger
	handler    slog.Handler
}

func (ch *captureHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return ch.handler.Enabled(ctx, level)
}

func (ch *captureHandler) Handle(ctx context.Context, record slog.Record) error { //nolint:gocritic // slog.Handler interface
	// Capture the message and level
	ch.testLogger.messages = append(ch.testLogger.messages, record.Message)
	ch.testLogger.levels = append(ch.testLogger.levels, record.Level)

	// Also call the original handler
	return ch.handler.Handle(ctx, record)
}

func (ch *captureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &captureHandler{
		testLogger: ch.testLogger,
		handler:    ch.handler.WithAttrs(attrs),
	}
}

func (ch *captureHandler) WithGroup(name string) slog.Handler {
	return &captureHandler{
		testLogger: ch.testLogger,
		handler:    ch.handler.WithGroup(name),
	}
}

type testCreateOrderInput struct {
	requestBody          map[string]any
	userID               string
	hasUserInContext     bool
	mockCreateOrderError error
}

type testGetOrderInput struct {
	orderID           string
	mockOrder         *domain.Order
	mockGetOrderError error
}

// Helper function to create context with user ID
func createContextWithUserID(userID string) context.Context {
	return context.WithValue(context.Background(), middleware.UserIDContextKey, userID)
}

func TestOrderHandler_CreateOrder(t *testing.T) {
	testUserID := "test-user-123"

	testCases := map[string]struct {
		input              testCreateOrderInput
		expectedStatus     int
		expectedError      string
		expectedLogMessage string
		expectedLogLevel   slog.Level
	}{
		"should create order successfully with valid request and user context": {
			input: testCreateOrderInput{
				requestBody: map[string]any{
					"name": "Test Order",
					"attributes": map[string]any{
						"priority": "high",
						"category": "electronics",
					},
				},
				userID:               testUserID,
				hasUserInContext:     true,
				mockCreateOrderError: nil,
			},
			expectedStatus: http.StatusCreated,
		},

		"should create order successfully with minimal request and set attributes": {
			input: testCreateOrderInput{
				requestBody: map[string]any{
					"name": "Minimal Order",
				},
				userID:               testUserID,
				hasUserInContext:     true,
				mockCreateOrderError: nil,
			},
			expectedStatus: http.StatusCreated,
		},

		"should return unauthorized when user ID not in context": {
			input: testCreateOrderInput{
				requestBody: map[string]any{
					"name": "Test Order",
				},
				hasUserInContext: false,
			},
			expectedStatus:     http.StatusUnauthorized,
			expectedError:      "User authentication is required",
			expectedLogMessage: "User ID not found in context",
			expectedLogLevel:   slog.LevelError,
		},

		"should return bad request when name is missing": {
			input: testCreateOrderInput{
				requestBody: map[string]any{
					"attributes": map[string]any{
						"category": "electronics",
					},
				},
				userID:           testUserID,
				hasUserInContext: true,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Name is required",
		},

		"should return bad request when name is empty": {
			input: testCreateOrderInput{
				requestBody: map[string]any{
					"name":       "",
					"attributes": map[string]any{},
				},
				userID:           testUserID,
				hasUserInContext: true,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Name is required",
		},

		"should return internal server error when repository fails": {
			input: testCreateOrderInput{
				requestBody: map[string]any{
					"name": "Failed Order",
				},
				userID:               testUserID,
				hasUserInContext:     true,
				mockCreateOrderError: errors.New("database connection failed"),
			},
			expectedStatus:     http.StatusInternalServerError,
			expectedError:      "An internal error occurred while processing your request",
			expectedLogMessage: "Failed to create order",
			expectedLogLevel:   slog.LevelError,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Initialize mock and test logger
			mockRepo := &mockOrderRepository{}
			testLogger := newTestLogger()
			logger := testLogger.getLogger()
			handler := NewOrderHandler(mockRepo, logger)

			// Setup mock behavior based on input
			if tc.input.requestBody["name"] != "" && tc.input.requestBody["name"] != nil && tc.input.hasUserInContext {
				mockRepo.On("CreateOrder", mock.Anything, mock.MatchedBy(func(order *domain.Order) bool {
					// Verify that owner and status are set correctly
					return order.Name == tc.input.requestBody["name"] &&
						order.Attributes["owner"] == tc.input.userID &&
						order.Attributes["status"] == OrderStatusCreated
				})).Return(tc.input.mockCreateOrderError)
			}

			// Prepare request
			requestBody, _ := json.Marshal(tc.input.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/orders", bytes.NewBuffer(requestBody))
			req.Header.Set("Content-Type", "application/json")

			// Set user ID in context if needed
			if tc.input.hasUserInContext {
				ctx := createContextWithUserID(tc.input.userID)
				req = req.WithContext(ctx)
			}

			w := httptest.NewRecorder()

			// Execute
			handler.CreateOrder(w, req)

			// Assert HTTP response
			assert.Equal(t, tc.expectedStatus, w.Code)

			if tc.expectedError != "" {
				var errorResponse ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errorResponse)
				assert.NoError(t, err)
				assert.Contains(t, errorResponse.Message, tc.expectedError)
			} else {
				var response CreateOrderResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.NotEmpty(t, response.ID)
				assert.Equal(t, tc.input.requestBody["name"], response.Name)

				// Verify owner and status are set
				assert.Equal(t, tc.input.userID, response.Attributes["owner"])
				assert.Equal(t, OrderStatusCreated, response.Attributes["status"])

				// Verify original attributes are preserved
				if tc.input.requestBody["attributes"] != nil {
					originalAttrs := tc.input.requestBody["attributes"].(map[string]any)
					for key, value := range originalAttrs {
						assert.Equal(t, value, response.Attributes[key])
					}
				}
			}

			// Assert log messages and levels
			if tc.expectedLogMessage != "" {
				assert.NotEmpty(t, testLogger.messages, "Expected log message but no logs were captured")

				// Check if the expected message exists in any of the captured messages
				found := false
				for i, message := range testLogger.messages {
					if message == tc.expectedLogMessage {
						assert.Equal(t, tc.expectedLogLevel, testLogger.levels[i])
						found = true
						break
					}
				}
				assert.True(t, found, "Expected log message '%s' not found in captured messages", tc.expectedLogMessage)
			}

			mockRepo.AssertExpectations(t)
			testLogger.reset()
		})
	}
}

func TestOrderHandler_CreateOrder_InvalidJSON(t *testing.T) {
	testUserID := "test-user-123"

	testCases := map[string]struct {
		requestBody    string
		expectedStatus int
		expectedError  string
	}{
		"should return bad request when JSON is invalid": {
			requestBody:    `{"name": "test"`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid request body",
		},

		"should return bad request when body is not JSON": {
			requestBody:    `invalid json`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid request body",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Initialize mock and logger
			mockRepo := &mockOrderRepository{}
			testLogger := newTestLogger()
			logger := testLogger.getLogger()
			handler := NewOrderHandler(mockRepo, logger)

			// Prepare request
			req := httptest.NewRequest(http.MethodPost, "/orders", bytes.NewBufferString(tc.requestBody))
			req.Header.Set("Content-Type", "application/json")

			// Set user ID in context
			ctx := createContextWithUserID(testUserID)
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()

			// Execute
			handler.CreateOrder(w, req)

			// Assert
			assert.Equal(t, tc.expectedStatus, w.Code)

			var errorResponse ErrorResponse
			err := json.Unmarshal(w.Body.Bytes(), &errorResponse)
			assert.NoError(t, err)
			assert.Contains(t, errorResponse.Error, tc.expectedError)

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestOrderHandler_GetOrderByID(t *testing.T) {
	validOrderID := uuid.New()
	testOrder := &domain.Order{
		ID:   validOrderID,
		Name: "Test Order",
		Attributes: map[string]any{
			"priority": "high",
			"category": "electronics",
		},
	}

	testCases := map[string]struct {
		input              testGetOrderInput
		expectedStatus     int
		expectedBody       *domain.Order
		expectedError      string
		expectedLogMessage string
		expectedLogLevel   slog.Level
	}{
		"should return order successfully when order exists": {
			input: testGetOrderInput{
				orderID:           validOrderID.String(),
				mockOrder:         testOrder,
				mockGetOrderError: nil,
			},
			expectedStatus: http.StatusOK,
			expectedBody:   testOrder,
		},

		"should return not found when order does not exist": {
			input: testGetOrderInput{
				orderID:   validOrderID.String(),
				mockOrder: nil,
				mockGetOrderError: &repository.NotFoundError{
					Resource: "order",
					Key:      "id",
					Value:    validOrderID.String(),
				},
			},
			expectedStatus:     http.StatusNotFound,
			expectedError:      "The requested order could not be found",
			expectedLogMessage: "Order not found",
			expectedLogLevel:   slog.LevelWarn,
		},

		"should return bad request when order ID is invalid": {
			input: testGetOrderInput{
				orderID: "invalid-uuid",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "ID must be a valid UUID",
		},

		"should return internal server error when repository fails": {
			input: testGetOrderInput{
				orderID:           validOrderID.String(),
				mockOrder:         nil,
				mockGetOrderError: errors.New("database connection failed"),
			},
			expectedStatus:     http.StatusInternalServerError,
			expectedError:      "An internal error occurred while retrieving the order",
			expectedLogMessage: "Failed to retrieve order",
			expectedLogLevel:   slog.LevelError,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Initialize mock and test logger
			mockRepo := &mockOrderRepository{}
			testLogger := newTestLogger()
			logger := testLogger.getLogger()
			handler := NewOrderHandler(mockRepo, logger)

			// Setup mock behavior based on input
			if tc.input.orderID != "invalid-uuid" {
				orderID, _ := uuid.Parse(tc.input.orderID)
				mockRepo.On("GetOrderByID", mock.Anything, orderID).Return(tc.input.mockOrder, tc.input.mockGetOrderError)
			}

			// Prepare request with mux router
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/orders/%s", tc.input.orderID), http.NoBody)
			w := httptest.NewRecorder()

			// Setup mux router to extract path variables
			router := http.NewServeMux()
			router.HandleFunc("GET /orders/{id}", handler.GetOrderByID)
			router.ServeHTTP(w, req)

			// Assert HTTP response
			assert.Equal(t, tc.expectedStatus, w.Code)

			if tc.expectedError != "" {
				var errorResponse ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errorResponse)
				assert.NoError(t, err)
				assert.Contains(t, errorResponse.Message, tc.expectedError)
			} else {
				var response domain.Order
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedBody.ID, response.ID)
				assert.Equal(t, tc.expectedBody.Name, response.Name)
				assert.Equal(t, tc.expectedBody.Attributes, response.Attributes)
			}

			// Assert log messages and levels
			if tc.expectedLogMessage != "" {
				assert.NotEmpty(t, testLogger.messages, "Expected log message but no logs were captured")

				// Check if the expected message exists in any of the captured messages
				found := false
				for i, message := range testLogger.messages {
					if message == tc.expectedLogMessage {
						assert.Equal(t, tc.expectedLogLevel, testLogger.levels[i])
						found = true
						break
					}
				}
				assert.True(t, found, "Expected log message '%s' not found in captured messages", tc.expectedLogMessage)
			}

			mockRepo.AssertExpectations(t)
			testLogger.reset()
		})
	}
}
