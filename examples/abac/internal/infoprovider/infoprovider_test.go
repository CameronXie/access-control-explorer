package infoprovider

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	ip "github.com/CameronXie/access-control-explorer/abac/infoprovider"
)

type testContextKey string

// mockInfoProvider is a mock implementation of InfoProvider for testing
type mockInfoProvider struct {
	mock.Mock
}

func (m *mockInfoProvider) GetInfo(ctx context.Context, req *ip.GetInfoRequest) (*ip.GetInfoResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	res := args.Get(0).(*ip.GetInfoResponse)

	if ctx.Value(testContextKey("test")) != nil {
		res.Info["test"] = ctx.Value(testContextKey("test"))
	}

	return res, args.Error(1)
}

func TestInfoProvider_GetInfo(t *testing.T) {
	testCases := map[string]struct {
		req                  *ip.GetInfoRequest
		mockInfoProviderResp *ip.GetInfoResponse
		mockInfoProviderErr  error
		setupContext         func() context.Context
		expectedResult       *ip.GetInfoResponse
		expectedError        string
	}{
		"should return error when request is nil": {
			req:            nil,
			setupContext:   func() context.Context { return context.Background() },
			expectedError:  "request cannot be nil",
			expectedResult: nil,
		},

		"should return info when info provider exists": {
			req: &ip.GetInfoRequest{
				InfoType: "user",
				Params:   "user123",
			},
			mockInfoProviderResp: &ip.GetInfoResponse{
				Info: map[string]any{
					"id":         "user123",
					"name":       "John Doe",
					"department": "engineering",
				},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: &ip.GetInfoResponse{
				Info: map[string]any{
					"id":         "user123",
					"name":       "John Doe",
					"department": "engineering",
				},
			},
		},

		"should return error when unsupported info type is requested": {
			req: &ip.GetInfoRequest{
				InfoType: "unsupported",
				Params:   "param123",
			},
			setupContext:   func() context.Context { return context.Background() },
			expectedError:  "unsupported info type unsupported",
			expectedResult: nil,
		},

		"should return error when provider returns error": {
			req: &ip.GetInfoRequest{
				InfoType: "user",
				Params:   "invalidUser",
			},
			mockInfoProviderErr: fmt.Errorf("user invalidUser not found"),
			setupContext:        func() context.Context { return context.Background() },
			expectedError:       "user invalidUser not found",
			expectedResult:      nil,
		},

		"should pass context to underlying provider": {
			req: &ip.GetInfoRequest{
				InfoType: "user",
				Params:   "contextTest",
			},
			mockInfoProviderResp: &ip.GetInfoResponse{
				Info: map[string]any{
					"id":         "user123",
					"name":       "John Doe",
					"department": "engineering",
				},
			},
			setupContext: func() context.Context {
				return context.WithValue(context.Background(), testContextKey("test"), "value")
			},
			expectedResult: &ip.GetInfoResponse{
				Info: map[string]any{
					"id":         "user123",
					"name":       "John Doe",
					"department": "engineering",
					"test":       "value",
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Create mock providers
			userProvider := new(mockInfoProvider)

			// Setup context
			ctx := tc.setupContext()

			// Setup mocks
			if tc.req != nil && tc.req.InfoType == "user" {
				userProvider.On("GetInfo", ctx, tc.req).Return(
					tc.mockInfoProviderResp,
					tc.mockInfoProviderErr,
				)
			}

			// Create an info provider
			p := NewInfoProvider(map[InfoType]ip.InfoProvider{
				"user": userProvider,
			})

			// Execute
			result, err := p.GetInfo(ctx, tc.req)

			// Assert
			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Equal(t, tc.expectedResult, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
			}

			// Verify mock expectations
			userProvider.AssertExpectations(t)
		})
	}
}
