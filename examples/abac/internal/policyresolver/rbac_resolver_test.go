package policyresolver

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/CameronXie/access-control-explorer/abac/decisionmaker"
)

func TestRoleProcessor_Process(t *testing.T) {
	rbacPolicyID := "rbac-policy"
	rbacPolicyVersion := "v1"

	testCases := map[string]struct {
		req            *decisionmaker.DecisionRequest
		setupContext   func() context.Context
		expectedResult []decisionmaker.PolicyIdReference
		expectedError  string
	}{
		"should return RBAC policy when subject has role attribute": {
			req: &decisionmaker.DecisionRequest{
				RequestID: uuid.New(),
				Subject: decisionmaker.Subject{
					ID: "user123",
					Attributes: map[string]any{
						"roles": "manager",
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
					ID:      rbacPolicyID,
					Version: rbacPolicyVersion,
				},
			},
		},

		"should return RBAC policy when subject has role attribute with other attributes": {
			req: &decisionmaker.DecisionRequest{
				RequestID: uuid.New(),
				Subject: decisionmaker.Subject{
					ID: "user456",
					Attributes: map[string]any{
						"roles":      "employee",
						"department": "engineering",
						"level":      5,
					},
				},
				Resource: decisionmaker.Resource{
					ID: "system",
				},
				Action: decisionmaker.Action{
					ID: "write",
				},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: []decisionmaker.PolicyIdReference{
				{
					ID:      rbacPolicyID,
					Version: rbacPolicyVersion,
				},
			},
		},

		"should return empty slice when subject has no role attribute": {
			req: &decisionmaker.DecisionRequest{
				RequestID: uuid.New(),
				Subject: decisionmaker.Subject{
					ID: "user789",
					Attributes: map[string]any{
						"department": "sales",
						"level":      3,
					},
				},
				Action: decisionmaker.Action{
					ID: "read",
				},
				Resource: decisionmaker.Resource{
					ID: "report1",
				},
			},
			setupContext:   func() context.Context { return context.Background() },
			expectedResult: []decisionmaker.PolicyIdReference{},
		},

		"should return empty slice when subject has no attributes": {
			req: &decisionmaker.DecisionRequest{
				RequestID: uuid.New(),
				Subject: decisionmaker.Subject{
					ID: "user999",
				},
				Resource: decisionmaker.Resource{
					ID: "document2",
				},
				Action: decisionmaker.Action{
					ID: "delete",
				},
			},
			setupContext:   func() context.Context { return context.Background() },
			expectedResult: []decisionmaker.PolicyIdReference{},
		},

		"should return empty slice when subject attributes is nil": {
			req: &decisionmaker.DecisionRequest{
				RequestID: uuid.New(),
				Subject: decisionmaker.Subject{
					ID:         "user000",
					Attributes: nil,
				},
				Resource: decisionmaker.Resource{
					ID: "resource1",
				},
				Action: decisionmaker.Action{
					ID: "execute",
				},
			},
			setupContext:   func() context.Context { return context.Background() },
			expectedResult: []decisionmaker.PolicyIdReference{},
		},

		"should return empty slice when request is nil": {
			req:            nil,
			setupContext:   func() context.Context { return context.Background() },
			expectedResult: nil,
			expectedError:  "decision request cannot be nil",
		},

		"should handle context cancellation": {
			req: &decisionmaker.DecisionRequest{
				RequestID: uuid.New(),
				Subject: decisionmaker.Subject{
					ID: "user123",
					Attributes: map[string]any{
						"roles": "admin",
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
					ID:      rbacPolicyID,
					Version: rbacPolicyVersion,
				},
			},
		},

		"should return RBAC policy when role attribute is empty string": {
			req: &decisionmaker.DecisionRequest{
				RequestID: uuid.New(),
				Subject: decisionmaker.Subject{
					ID: "user456",
					Attributes: map[string]any{
						"roles": "",
					},
				},
				Resource: decisionmaker.Resource{
					ID: "document3",
				},
				Action: decisionmaker.Action{
					ID: "read",
				},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: []decisionmaker.PolicyIdReference{
				{
					ID:      rbacPolicyID,
					Version: rbacPolicyVersion,
				},
			},
		},

		"should return RBAC policy when role attribute is nil": {
			req: &decisionmaker.DecisionRequest{
				RequestID: uuid.New(),
				Subject: decisionmaker.Subject{
					ID: "user789",
					Attributes: map[string]any{
						"roles": nil,
					},
				},
				Resource: decisionmaker.Resource{
					ID: "file1",
				},
				Action: decisionmaker.Action{
					ID: "upload",
				},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: []decisionmaker.PolicyIdReference{
				{
					ID:      rbacPolicyID,
					Version: rbacPolicyVersion,
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			resolver := NewRBACResolver(rbacPolicyID, rbacPolicyVersion)

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
