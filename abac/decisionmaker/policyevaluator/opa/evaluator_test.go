package opa

import (
	"context"
	"testing"

	"github.com/CameronXie/access-control-explorer/abac/decisionmaker"
	"github.com/stretchr/testify/assert"
)

func TestEvaluator_Evaluate(t *testing.T) {
	tests := map[string]struct {
		query          string
		request        *decisionmaker.DecisionRequest
		policies       []decisionmaker.Policy
		expectedResult *decisionmaker.EvaluationResult
		expectedError  string
	}{
		"nil request should return error": {
			query:   "data.abac.result",
			request: nil,
			policies: []decisionmaker.Policy{
				getSubjectPolicy(),
			},
			expectedError: "decision request cannot be nil",
		},

		"empty policies should return error": {
			query:         "data.abac.result",
			request:       newTestRequest([]string{"admin"}, "read"),
			policies:      []decisionmaker.Policy{},
			expectedError: "no policies provided for evaluation",
		},

		"invalid policy should return error": {
			query:   "data.abac.result",
			request: newTestRequest([]string{"admin"}, "read"),
			policies: []decisionmaker.Policy{{
				ID:      "invalid",
				Content: []byte("package"),
			}},
			expectedError: `policy evaluation failed: 1 error occurred: policy_invalid:1: rego_parse_error: unexpected eof token`,
		},

		"policy has no result should return error": {
			query:   "data.abac.result",
			request: newTestRequest([]string{"admin"}, "read"),
			policies: []decisionmaker.Policy{{
				ID:      "invalid",
				Content: []byte("package abac"),
			}},
			expectedError: "no evaluation results returned from policy engine",
		},

		"admin user should get permit decision with obligations": {
			query:    "data.abac.result",
			request:  newTestRequest([]string{"admin"}, "read"),
			policies: []decisionmaker.Policy{getSubjectPolicy()},
			expectedResult: &decisionmaker.EvaluationResult{
				Decision: decisionmaker.Permit,
				Status: decisionmaker.Status{
					Code:    "OK",
					Message: "Access granted - Administrative privileges verified for user",
				},
				Obligations: []decisionmaker.Obligation{
					{
						ID: "audit_logging",
						Attributes: map[string]any{
							"level":   "INFO",
							"message": "Administrative access granted to user with verified admin role",
						},
					},
				},
			},
		},

		"customer with update action should get deny": {
			query:    "data.abac.result",
			request:  newTestRequest([]string{"customer"}, "update"),
			policies: []decisionmaker.Policy{getSubjectPolicy(), getResourcePolicy()},
			expectedResult: &decisionmaker.EvaluationResult{
				Decision: decisionmaker.Deny,
				Status: decisionmaker.Status{
					Code:    "OK",
					Message: "Access denied - Customers are not authorized to update product information",
				},
				Obligations: []decisionmaker.Obligation{
					{
						ID: "audit_logging",
						Attributes: map[string]any{
							"level":   "WARN",
							"message": "Customer attempted unauthorized product update operation",
						},
					},
				},
			},
		},

		"customer with create action should get not applicable": {
			query:    "data.abac.result",
			request:  newTestRequest([]string{"customer"}, "create"),
			policies: []decisionmaker.Policy{getSubjectPolicy()},
			expectedResult: &decisionmaker.EvaluationResult{
				Decision: decisionmaker.NotApplicable,
				Status: decisionmaker.Status{
					Code:    "PolicyNotFound",
					Message: "No applicable access control policy found for the requested resource and action",
				},
				Obligations: []decisionmaker.Obligation{
					{
						ID: "audit_logging",
						Attributes: map[string]any{
							"level":   "WARN",
							"message": "Access request processed without matching any specific authorization policy",
						},
					},
				},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := NewEvaluator(tc.query).Evaluate(context.Background(), tc.request, tc.policies)

			// Verify error cases
			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				return
			}

			// Verify success cases
			assert.NoError(t, err)
			assert.EqualValues(t, *tc.expectedResult, *result)
		})
	}
}

func TestEvaluator_ConvertResult(t *testing.T) {
	tests := map[string]struct {
		input          any
		expectedError  string
		expectedResult *decisionmaker.EvaluationResult
	}{
		// JSON unmarshaling error test
		"invalid input should return error": {
			input:          `{`,
			expectedError:  "failed to unmarshal evaluation result: json: cannot unmarshal string",
			expectedResult: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := convertResult(tc.input)

			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				return
			}

			assert.NoError(t, err)
			assert.EqualValues(t, *tc.expectedResult, *result)
		})
	}
}

// newTestRequest creates a standard test request with specified roles and action
func newTestRequest(roles []string, actionID string) *decisionmaker.DecisionRequest {
	return &decisionmaker.DecisionRequest{
		Subject: decisionmaker.Subject{
			ID:   "user123",
			Type: "user",
			Attributes: map[string]any{
				"roles": roles,
			},
		},
		Action: decisionmaker.Action{
			ID: actionID,
		},
		Resource: decisionmaker.Resource{
			ID:   "product-123",
			Type: "product",
			Attributes: map[string]any{
				"sku":   "123456",
				"price": 123.45,
			},
		},
	}
}

// getSubjectPolicy returns a Rego policy that handles subject-based authorization
// Includes admin access rules and default fallback behavior
func getSubjectPolicy() decisionmaker.Policy {
	content := `
package abac

# Default policy result when no specific rules match
# This ensures every evaluation returns a decision rather than undefined
default result := {
	"decision": "NotApplicable",
	"status": {
		"code": "PolicyNotFound",
		"message": "No applicable access control policy found for the requested resource and action",
	},
	"obligations": [{
		"id": "audit_logging",
		"attributes": {
			"level": "WARN",
			"message": "Access request processed without matching any specific authorization policy",
		},
	}],
}

# Administrative access rule
# Grants full access to users with admin role in their attributes
# Returns Permit decision with mandatory audit logging obligation
result := {
	"decision": "Permit",
	"status": {
		"code": "OK",
		"message": "Access granted - Administrative privileges verified for user",
	},
	"obligations": [{
		"id": "audit_logging",
		"attributes": {
			"level": "INFO",
			"message": "Administrative access granted to user with verified admin role"
		},
	}],
} if {
	user_is_admin
}

# Helper rule to determine if the requesting user has administrative privileges
# Checks if "admin" role exists in the subject's role attributes
# This separation makes the policy more readable and maintainable
user_is_admin if {
	"admin" in input.subject.attributes.roles
}`
	return decisionmaker.Policy{
		ID:      "subject-policy",
		Version: "1.0",
		Content: []byte(content),
	}
}

// getResourcePolicy returns a Rego policy that handles resource-specific restrictions
// Implements customer access limitations for product updates
func getResourcePolicy() decisionmaker.Policy {
	content := `
package abac

# Customer access restriction rule for product updates
# Denies update operations on product resources when requested by customer-only users
# This enforces business rule that customers cannot modify product information
result := {
	"decision": "Deny",
	"status": {
		"code": "OK",
		"message": "Access denied - Customers are not authorized to update product information",
	},
	"obligations": [{
		"id": "audit_logging",
		"attributes": {
			"level": "WARN",
			"message": "Customer attempted unauthorized product update operation",
		},
	}],
} if {
	user_is_customer
	input.action.id == "update"
	input.resource.type == "product"
}

# Helper rule to identify customer-only users
# This ensures users with customer + other roles (like admin) are not restricted
user_is_customer if {
	"customer" in input.subject.attributes.roles
	count(input.subject.attributes.roles) == 1
}
`
	return decisionmaker.Policy{
		ID:      "resource-policy",
		Version: "1.0",
		Content: []byte(content),
	}
}
