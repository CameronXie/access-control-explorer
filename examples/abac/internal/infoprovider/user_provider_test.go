//nolint:dupl // Similar structure to order_provider by design: separate domain providers share flow now.
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

// mockUserAttributesRepository is a mock implementation of UserAttributesRepository
type mockUserAttributesRepository struct {
	mock.Mock
}

func (m *mockUserAttributesRepository) GetUserAttributesByID(ctx context.Context, id uuid.UUID) (map[string]any, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]any), args.Error(1)
}

func TestNewUserProvider(t *testing.T) {
	mockRepo := new(mockUserAttributesRepository)
	provider := NewUserProvider(mockRepo)

	assert.NotNil(t, provider)
	assert.IsType(t, &userProvider{}, provider)
}

func TestUserProvider_GetInfo(t *testing.T) {
	userID := uuid.New()
	anotherUserID := uuid.New()

	testCases := map[string]struct {
		request          *ip.GetInfoRequest
		mockUserResp     map[string]any
		mockUserErr      error
		expectedResponse *ip.GetInfoResponse
		expectedError    string
		shouldCallMock   bool
		expectedUserID   uuid.UUID
	}{
		"should return user attributes with roles as string array": {
			request: &ip.GetInfoRequest{
				Params: userID.String(),
			},
			mockUserResp: map[string]any{
				"roles":        []string{"manager", "reviewer"},
				"department":   "sales",
				"region":       "europe",
				"level":        "manager",
				"team_members": 15,
				"budget_limit": 50000.75,
				"preferences": map[string]any{
					"theme":    "dark",
					"language": "en",
					"timezone": "UTC+1",
					"notifications": map[string]any{
						"email": true,
						"sms":   false,
						"push":  true,
					},
				},
			},
			expectedResponse: &ip.GetInfoResponse{
				Info: map[string]any{
					"roles":        []string{"manager", "reviewer"},
					"department":   "sales",
					"region":       "europe",
					"level":        "manager",
					"team_members": 15,
					"budget_limit": 50000.75,
					"preferences": map[string]any{
						"theme":    "dark",
						"language": "en",
						"timezone": "UTC+1",
						"notifications": map[string]any{
							"email": true,
							"sms":   false,
							"push":  true,
						},
					},
				},
			},
			shouldCallMock: true,
			expectedUserID: userID,
		},

		"should return user attributes with empty roles array": {
			request: &ip.GetInfoRequest{
				Params: userID.String(),
			},
			mockUserResp: map[string]any{
				"roles":      []string{},
				"department": "hr",
				"level":      "junior",
				"active":     true,
			},
			expectedResponse: &ip.GetInfoResponse{
				Info: map[string]any{
					"roles":      []string{},
					"department": "hr",
					"level":      "junior",
					"active":     true,
				},
			},
			shouldCallMock: true,
			expectedUserID: userID,
		},

		"should return empty attributes when user has no attributes": {
			request: &ip.GetInfoRequest{
				Params: userID.String(),
			},
			mockUserResp: map[string]any{
				"roles": []string{},
			},
			expectedResponse: &ip.GetInfoResponse{
				Info: map[string]any{
					"roles": []string{},
				},
			},
			shouldCallMock: true,
			expectedUserID: userID,
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
			expectedError:  "user ID parameter must be a string, got int: 12345",
			shouldCallMock: false,
		},

		"should return error when params is not valid UUID": {
			request: &ip.GetInfoRequest{
				Params: "invalid-uuid",
			},
			expectedError:  "user ID must be a valid UUID format, got: invalid-uuid",
			shouldCallMock: false,
		},

		"should return error when repository returns NotFoundError": {
			request: &ip.GetInfoRequest{
				Params: anotherUserID.String(),
			},
			mockUserErr: &repository.NotFoundError{
				Resource: "user",
				Key:      "id",
				Value:    anotherUserID.String(),
			},
			expectedError:  fmt.Sprintf("user with id %s not found", anotherUserID.String()),
			shouldCallMock: true,
			expectedUserID: anotherUserID,
		},

		"should return error when repository returns database error": {
			request: &ip.GetInfoRequest{
				Params: userID.String(),
			},
			mockUserErr:    errors.New("database connection failed"),
			expectedError:  "database connection failed",
			shouldCallMock: true,
			expectedUserID: userID,
		},

		"should handle different UUID formats": {
			request: &ip.GetInfoRequest{
				Params: userID.String(),
			},
			mockUserResp: map[string]any{
				"roles":      []string{"user"},
				"department": "support",
				"active":     true,
			},
			expectedResponse: &ip.GetInfoResponse{
				Info: map[string]any{
					"roles":      []string{"user"},
					"department": "support",
					"active":     true,
				},
			},
			shouldCallMock: true,
			expectedUserID: userID,
		},

		"should handle params as interface{} containing string": {
			request: &ip.GetInfoRequest{
				Params: any(userID.String()),
			},
			mockUserResp: map[string]any{
				"roles":      []string{"test"},
				"department": "testing",
				"temporary":  true,
			},
			expectedResponse: &ip.GetInfoResponse{
				Info: map[string]any{
					"roles":      []string{"test"},
					"department": "testing",
					"temporary":  true,
				},
			},
			shouldCallMock: true,
			expectedUserID: userID,
		},

		"should handle user with mixed data types": {
			request: &ip.GetInfoRequest{
				Params: userID.String(),
			},
			mockUserResp: map[string]any{
				"roles":          []string{"developer", "reviewer"},
				"employee_id":    12345,
				"salary":         75000.50,
				"is_remote":      true,
				"start_date":     "2023-01-15",
				"skills":         []string{"Go", "JavaScript", "Python", "Docker"},
				"certifications": []any{"AWS Solutions Architect", 2023, true},
				"project_stats": map[string]any{
					"projects_completed": 15,
					"avg_rating":         4.8,
					"languages_used":     []string{"Go", "TypeScript", "SQL"},
				},
			},
			expectedResponse: &ip.GetInfoResponse{
				Info: map[string]any{
					"roles":          []string{"developer", "reviewer"},
					"employee_id":    12345,
					"salary":         75000.50,
					"is_remote":      true,
					"start_date":     "2023-01-15",
					"skills":         []string{"Go", "JavaScript", "Python", "Docker"},
					"certifications": []any{"AWS Solutions Architect", 2023, true},
					"project_stats": map[string]any{
						"projects_completed": 15,
						"avg_rating":         4.8,
						"languages_used":     []string{"Go", "TypeScript", "SQL"},
					},
				},
			},
			shouldCallMock: true,
			expectedUserID: userID,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Create mock repository
			mockRepo := new(mockUserAttributesRepository)

			// Setup mocks in test case loop
			if tc.shouldCallMock {
				mockRepo.On("GetUserAttributesByID", mock.Anything, tc.expectedUserID).Return(
					tc.mockUserResp,
					tc.mockUserErr,
				)
			}

			provider := NewUserProvider(mockRepo)

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
