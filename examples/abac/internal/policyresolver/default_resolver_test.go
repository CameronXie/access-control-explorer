package policyresolver

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/CameronXie/access-control-explorer/abac/decisionmaker"
)

func TestDefaultProcessor_Process(t *testing.T) {
	defaultPolicyID := "default-deny-policy"
	defaultPolicyVersion := "v1"

	testCases := map[string]struct {
		req            *decisionmaker.DecisionRequest
		setupContext   func() context.Context
		expectedResult []decisionmaker.PolicyIdReference
		expectedError  string
	}{
		"should return default policy for basic request": {
			req: &decisionmaker.DecisionRequest{
				RequestID: uuid.New(),
				Subject: decisionmaker.Subject{
					ID: "user123",
					Attributes: map[string]any{
						"role": "manager",
					},
				},
				Action: decisionmaker.Action{
					ID: "read",
				},
				Resource: decisionmaker.Resource{
					ID: "document1",
				},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: []decisionmaker.PolicyIdReference{
				{
					ID:      defaultPolicyID,
					Version: defaultPolicyVersion,
				},
			},
		},

		"should return error when request is nil": {
			req:            nil,
			setupContext:   func() context.Context { return context.Background() },
			expectedResult: nil,
			expectedError:  "decision request cannot be nil",
		},

		"should return default policy even with cancelled context": {
			req: &decisionmaker.DecisionRequest{
				RequestID: uuid.New(),
				Subject: decisionmaker.Subject{
					ID: "user123",
					Attributes: map[string]any{
						"role": "admin",
					},
				},
				Resource: decisionmaker.Resource{
					ID: "system",
				},
				Action: decisionmaker.Action{
					ID: "manage",
				},
			},
			setupContext: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			expectedResult: []decisionmaker.PolicyIdReference{
				{
					ID:      defaultPolicyID,
					Version: defaultPolicyVersion,
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			resolver := NewDefaultResolver(defaultPolicyID, defaultPolicyVersion)

			// Setup context
			ctx := tc.setupContext()

			// Execute
			result, err := resolver.Resolve(ctx, tc.req)

			// Assert
			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, result)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}
