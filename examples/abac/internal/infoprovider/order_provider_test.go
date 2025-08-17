//nolint:dupl // Similar structure to user_provider by design: separate domain providers share flow now.
package infoprovider

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/CameronXie/access-control-explorer/examples/abac/internal/repository"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	ip "github.com/CameronXie/access-control-explorer/abac/infoprovider"
)

// mockOrderAttributesRepository is a mock implementation of OrderAttributesRepository
type mockOrderAttributesRepository struct {
	mock.Mock
}

func (m *mockOrderAttributesRepository) GetOrderAttributesByID(ctx context.Context, id uuid.UUID) (map[string]any, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]any), args.Error(1)
}

func TestNewOrderProvider(t *testing.T) {
	mockRepo := new(mockOrderAttributesRepository)
	provider := NewOrderProvider(mockRepo)

	assert.NotNil(t, provider)
	assert.IsType(t, &orderProvider{}, provider)
}

func TestOrderProvider_GetInfo(t *testing.T) {
	orderID := uuid.New()
	anotherOrderID := uuid.New()

	testCases := map[string]struct {
		request          *ip.GetInfoRequest
		mockOrderResp    map[string]any
		mockOrderErr     error
		expectedResponse *ip.GetInfoResponse
		expectedError    string
		shouldCallMock   bool
		expectedOrderID  uuid.UUID
	}{
		"should return order attributes when valid order ID is provided": {
			request: &ip.GetInfoRequest{
				Params: orderID.String(),
			},
			mockOrderResp: map[string]any{
				"category":    "premium",
				"price":       1999.99,
				"currency":    "USD",
				"user_id":     "user_123",
				"total_items": 5,
				"status":      "processing",
				"shipping": map[string]any{
					"address": "123 Main St",
					"city":    "New York",
					"urgent":  true,
				},
			},
			expectedResponse: &ip.GetInfoResponse{
				Info: map[string]any{
					"category":    "premium",
					"price":       1999.99,
					"currency":    "USD",
					"user_id":     "user_123",
					"total_items": 5,
					"status":      "processing",
					"shipping": map[string]any{
						"address": "123 Main St",
						"city":    "New York",
						"urgent":  true,
					},
				},
			},
			shouldCallMock:  true,
			expectedOrderID: orderID,
		},

		"should return empty attributes when order has no attributes": {
			request: &ip.GetInfoRequest{
				Params: orderID.String(),
			},
			mockOrderResp: map[string]any{},
			expectedResponse: &ip.GetInfoResponse{
				Info: map[string]any{},
			},
			shouldCallMock:  true,
			expectedOrderID: orderID,
		},

		"should return error when request is nil": {
			request:        nil,
			expectedError:  "request cannot be nil",
			shouldCallMock: false,
		},

		"should return error when params is not string": {
			request: &ip.GetInfoRequest{
				Params: 12345,
			},
			expectedError:  "order ID parameter must be a string, got int: 12345",
			shouldCallMock: false,
		},

		"should return error when params is not valid UUID": {
			request: &ip.GetInfoRequest{
				Params: "invalid-uuid",
			},
			expectedError:  "order ID must be a valid UUID format, got: invalid-uuid",
			shouldCallMock: false,
		},

		"should return error when repository returns NotFoundError": {
			request: &ip.GetInfoRequest{
				Params: anotherOrderID.String(),
			},
			mockOrderErr: &repository.NotFoundError{
				Resource: "order",
				Key:      "id",
				Value:    anotherOrderID.String(),
			},
			expectedError:   fmt.Sprintf("order with id %s not found", anotherOrderID.String()),
			shouldCallMock:  true,
			expectedOrderID: anotherOrderID,
		},

		"should return error when repository returns database error": {
			request: &ip.GetInfoRequest{
				Params: orderID.String(),
			},
			mockOrderErr:    errors.New("database connection failed"),
			expectedError:   "database connection failed",
			shouldCallMock:  true,
			expectedOrderID: orderID,
		},

		"should handle different UUID formats": {
			request: &ip.GetInfoRequest{
				Params: orderID.String(),
			},
			mockOrderResp: map[string]any{
				"category": "standard",
				"price":    99.99,
			},
			expectedResponse: &ip.GetInfoResponse{
				Info: map[string]any{
					"category": "standard",
					"price":    99.99,
				},
			},
			shouldCallMock:  true,
			expectedOrderID: orderID,
		},

		"should handle params as interface{} containing string": {
			request: &ip.GetInfoRequest{
				Params: any(orderID.String()),
			},
			mockOrderResp: map[string]any{
				"category": "test",
				"price":    49.99,
			},
			expectedResponse: &ip.GetInfoResponse{
				Info: map[string]any{
					"category": "test",
					"price":    49.99,
				},
			},
			shouldCallMock:  true,
			expectedOrderID: orderID,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Create mock repository
			mockRepo := new(mockOrderAttributesRepository)

			// Setup mocks in test case loop
			if tc.shouldCallMock {
				mockRepo.On("GetOrderAttributesByID", mock.Anything, tc.expectedOrderID).Return(
					tc.mockOrderResp,
					tc.mockOrderErr,
				)
			}

			provider := NewOrderProvider(mockRepo)

			// Execute
			response, err := provider.GetInfo(context.Background(), tc.request)

			// Assert
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				assert.EqualValues(t, tc.expectedResponse, response)
			}

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}
