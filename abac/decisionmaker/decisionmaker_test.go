//nolint:lll // unit tests
package decisionmaker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/CameronXie/access-control-explorer/abac/policyprovider"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations
type mockPolicyProvider struct {
	mock.Mock
}

func (m *mockPolicyProvider) GetPolicies(
	ctx context.Context,
	reqs []policyprovider.GetPolicyRequest,
) ([]policyprovider.PolicyResponse, error) {
	args := m.Called(ctx, reqs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]policyprovider.PolicyResponse), args.Error(1)
}

type mockPolicyEvaluator struct {
	mock.Mock
}

func (m *mockPolicyEvaluator) Evaluate(ctx context.Context, req *DecisionRequest, policies []Policy) (*EvaluationResult, error) {
	args := m.Called(ctx, req, policies)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*EvaluationResult), args.Error(1)
}

type mockPolicyResolver struct {
	mock.Mock
	delay time.Duration
}

func (m *mockPolicyResolver) Resolve(ctx context.Context, req *DecisionRequest) ([]PolicyIdReference, error) {
	// Simulate processing delay if configured
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
			// Continue with processing after delay
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]PolicyIdReference), args.Error(1)
}

type mockPolicyResolverConfig struct {
	delay        time.Duration
	policyIdRefs []PolicyIdReference
	err          error
}

// TestDecisionMaker_MakeDecision tests the DecisionMaker's MakeDecision method
func TestDecisionMaker_MakeDecision(t *testing.T) {
	// Common test variables
	fixedUUID := uuid.New()

	// Standard request used across tests
	standardRequest := &DecisionRequest{
		RequestID: fixedUUID,
		Subject: Subject{
			ID:   "user123",
			Type: "user",
			Attributes: map[string]any{
				"roles": []string{"admin", "user"},
			},
		},
		Resource: Resource{
			ID:   "resource456",
			Type: "document",
		},
		Action: Action{
			ID: "read",
		},
	}

	// Mock policy responses
	policyResponses := []policyprovider.PolicyResponse{
		{
			ID:      "policy1",
			Version: "1.0",
			Content: []byte(`{"policy": "content1"}`),
		},
		{
			ID:      "policy2",
			Version: "1.0",
			Content: []byte(`{"policy": "content2"}`),
		},
	}

	// Define test cases
	tests := map[string]struct {
		request                 *DecisionRequest
		policyResolverConfigs   []*mockPolicyResolverConfig
		policyResolveErr        bool
		policyProviderResponses []policyprovider.PolicyResponse
		policyRetrievalFail     error
		evaluationResult        *EvaluationResult
		evaluatorError          error
		expectedResponse        *DecisionResponse
		expectedError           string
	}{
		"should return error when request is nil": {
			request:       nil,
			expectedError: "decision request cannot be nil",
		},

		"should return indeterminate decision when no resolvers configured": {
			request: standardRequest,
			expectedResponse: &DecisionResponse{
				RequestID: fixedUUID,
				Decision:  Indeterminate,
				Status: &Status{
					Code:    StatusProcessingError,
					Message: "Failed to resolve policies: no policy resolve processors configured",
				},
				EvaluatedAt: time.Now(),
			},
		},

		"should return indeterminate decision when resolver fails": {
			request: standardRequest,
			policyResolverConfigs: []*mockPolicyResolverConfig{
				{
					policyIdRefs: []PolicyIdReference{{ID: "policy1", Version: "1.0"}},
					err:          errors.New("resolver error"),
				},
			},
			policyResolveErr: true,
			expectedResponse: &DecisionResponse{
				RequestID: fixedUUID,
				Decision:  Indeterminate,
				Status: &Status{
					Code:    StatusProcessingError,
					Message: "Failed to resolve policies: resolver error",
				},
				EvaluatedAt: time.Now(),
			},
		},

		"should return not applicable decision when no applicable policies found": {
			request: standardRequest,
			policyResolverConfigs: []*mockPolicyResolverConfig{
				{policyIdRefs: []PolicyIdReference{}},
			},
			expectedResponse: &DecisionResponse{
				RequestID: fixedUUID,
				Decision:  NotApplicable,
				Status: &Status{
					Code:    StatusPolicyNotFound,
					Message: "No applicable policies found for the request",
				},
				EvaluatedAt: time.Now(),
			},
		},

		"should return indeterminate decision when policy retrieval fails": {
			request: standardRequest,
			policyResolverConfigs: []*mockPolicyResolverConfig{
				{policyIdRefs: []PolicyIdReference{{ID: "policy1", Version: "1.0"}}},
				{policyIdRefs: []PolicyIdReference{{ID: "policy2", Version: "1.0"}}},
			},
			policyRetrievalFail: errors.New("provider error"),
			expectedResponse: &DecisionResponse{
				RequestID: fixedUUID,
				Decision:  Indeterminate,
				Status: &Status{
					Code:    StatusProcessingError,
					Message: "Failed to retrieve policies: failed to retrieve policies: provider error",
				},
				EvaluatedAt: time.Now(),
				PolicyIdReferences: []PolicyIdReference{
					{ID: "policy1", Version: "1.0"},
					{ID: "policy2", Version: "1.0"},
				},
			},
		},

		"should return indeterminate decision when policy evaluation fails": {
			request: standardRequest,
			policyResolverConfigs: []*mockPolicyResolverConfig{
				{policyIdRefs: []PolicyIdReference{{ID: "policy1", Version: "1.0"}}},
				{policyIdRefs: []PolicyIdReference{{ID: "policy2", Version: "1.0"}}},
			},
			policyProviderResponses: policyResponses,
			evaluatorError:          errors.New("evaluator error"),
			expectedResponse: &DecisionResponse{
				RequestID: fixedUUID,
				Decision:  Indeterminate,
				Status: &Status{
					Code:    StatusEvaluationError,
					Message: "Policy evaluation failed: evaluator error",
				},
				EvaluatedAt: time.Now(),
				PolicyIdReferences: []PolicyIdReference{
					{ID: "policy1", Version: "1.0"},
					{ID: "policy2", Version: "1.0"},
				},
			},
		},

		"should return permit decision with obligations and advice": {
			request: standardRequest,
			policyResolverConfigs: []*mockPolicyResolverConfig{
				{policyIdRefs: []PolicyIdReference{{ID: "policy1", Version: "1.0"}, {ID: "policy2", Version: "1.0"}}},
			},
			policyProviderResponses: policyResponses,
			evaluationResult: &EvaluationResult{
				Decision: Permit,
				Status: Status{
					Code:    StatusOK,
					Message: "Access permitted",
				},
				Obligations: []Obligation{
					{
						ID: "log-access",
						Attributes: map[string]any{
							"level": "info",
						},
					},
				},
				Advice: []Advice{
					{
						ID: "remind-confidentiality",
						Attributes: map[string]any{
							"message": "This document is confidential",
						},
					},
				},
			},
			expectedResponse: &DecisionResponse{
				RequestID: fixedUUID,
				Decision:  Permit,
				Status: &Status{
					Code:    StatusOK,
					Message: "Access permitted",
				},
				Obligations: []Obligation{
					{
						ID: "log-access",
						Attributes: map[string]any{
							"level": "info",
						},
					},
				},
				Advice: []Advice{
					{
						ID: "remind-confidentiality",
						Attributes: map[string]any{
							"message": "This document is confidential",
						},
					},
				},
				EvaluatedAt: time.Now(),
				PolicyIdReferences: []PolicyIdReference{
					{ID: "policy1", Version: "1.0"},
					{ID: "policy2", Version: "1.0"},
				},
			},
		},

		"should return deny decision when policy evaluation denies access": {
			request: standardRequest,
			policyResolverConfigs: []*mockPolicyResolverConfig{
				{policyIdRefs: []PolicyIdReference{{ID: "policy1", Version: "1.0"}}},
			},
			policyProviderResponses: []policyprovider.PolicyResponse{policyResponses[0]},
			evaluationResult: &EvaluationResult{
				Decision: Deny,
				Status: Status{
					Code:    StatusOK,
					Message: "Access denied",
				},
			},
			expectedResponse: &DecisionResponse{
				RequestID: fixedUUID,
				Decision:  Deny,
				Status: &Status{
					Code:    StatusOK,
					Message: "Access denied",
				},
				EvaluatedAt: time.Now(),
				PolicyIdReferences: []PolicyIdReference{
					{ID: "policy1", Version: "1.0"},
				},
			},
		},

		"should handle multiple resolvers returning unique policies": {
			request: standardRequest,
			policyResolverConfigs: []*mockPolicyResolverConfig{
				{policyIdRefs: []PolicyIdReference{{ID: "policy1", Version: "1.0"}, {ID: "policy2", Version: "1.0"}}},
			},
			policyProviderResponses: policyResponses,
			evaluationResult: &EvaluationResult{
				Decision: Permit,
				Status: Status{
					Code:    StatusOK,
					Message: "Access permitted",
				},
			},
			expectedResponse: &DecisionResponse{
				RequestID: fixedUUID,
				Decision:  Permit,
				Status: &Status{
					Code:    StatusOK,
					Message: "Access permitted",
				},
				EvaluatedAt: time.Now(),
				PolicyIdReferences: []PolicyIdReference{
					{ID: "policy1", Version: "1.0"},
					{ID: "policy2", Version: "1.0"},
				},
			},
		},

		"should return error when resolvers return duplicate policy with same version": {
			request: standardRequest,
			policyResolverConfigs: []*mockPolicyResolverConfig{
				{policyIdRefs: []PolicyIdReference{{ID: "policy1", Version: "1.0"}}},
				{policyIdRefs: []PolicyIdReference{{ID: "policy1", Version: "1.0"}}},
			},
			policyResolveErr: true,
			expectedResponse: &DecisionResponse{
				RequestID: fixedUUID,
				Decision:  Indeterminate,
				Status: &Status{
					Code:    StatusProcessingError,
					Message: "Failed to resolve policies: duplicate policy reference detected: policy 'policy1' version '1.0' returned by multiple processors",
				},
				EvaluatedAt: time.Now(),
			},
		},

		"should return error when resolvers return duplicate policy with different versions": {
			request: standardRequest,
			policyResolverConfigs: []*mockPolicyResolverConfig{
				{delay: 0, policyIdRefs: []PolicyIdReference{{ID: "policy1", Version: "1.0"}}},
				{delay: 50 * time.Millisecond, policyIdRefs: []PolicyIdReference{{ID: "policy1", Version: "2.0"}}},
			},
			policyResolveErr: true,
			expectedResponse: &DecisionResponse{
				RequestID: fixedUUID,
				Decision:  Indeterminate,
				Status: &Status{
					Code:    StatusProcessingError,
					Message: "Failed to resolve policies: duplicate policy ID 'policy1' found: existing version '1.0', conflicting version '2.0'",
				},
				EvaluatedAt: time.Now(),
			},
		},
	}

	// Run tests
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Create mocks
			mockProvider := new(mockPolicyProvider)
			mockEvaluator := new(mockPolicyEvaluator)
			resolvers := make([]*mockPolicyResolver, 0)

			// Create processors and configure mocks
			options := make([]Option, 0)
			var allPolicyIdRefs []PolicyIdReference

			if tc.request != nil {
				for _, config := range tc.policyResolverConfigs {
					resolver := &mockPolicyResolver{delay: config.delay}

					resolver.On("Resolve", mock.Anything, tc.request).Return(config.policyIdRefs, config.err)
					resolvers = append(resolvers, resolver)
					allPolicyIdRefs = append(allPolicyIdRefs, config.policyIdRefs...)
					options = append(options, WithPolicyResolver(resolver))
				}

				if len(allPolicyIdRefs) > 0 && tc.policyResolveErr == false {
					mockProvider.On(
						"GetPolicies",
						mock.Anything,
						mock.Anything,
					).Return(tc.policyProviderResponses, tc.policyRetrievalFail)

					if tc.policyRetrievalFail == nil {
						mockEvaluator.On(
							"Evaluate",
							mock.Anything,
							tc.request,
							mock.Anything,
						).Return(tc.evaluationResult, tc.evaluatorError)
					}
				}
			}

			// Create the decision maker with processors
			dm := NewDecisionMaker(mockProvider, mockEvaluator, options...)

			// Execute the method under test
			response, err := dm.MakeDecision(context.Background(), tc.request)

			// Verify error
			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				return
			}

			// Verify response using our custom assertion
			assertResponseMatch(t, tc.expectedResponse, response)
			assert.NoError(t, err)

			// Verify that all expected mock calls were made
			mockProvider.AssertExpectations(t)
			mockEvaluator.AssertExpectations(t)
			for _, resolver := range resolvers {
				resolver.AssertExpectations(t)
			}
		})
	}
}

// TestDecisionMaker_GetPolicies tests the getPolicies helper method
func TestDecisionMaker_GetPolicies(t *testing.T) {
	tests := map[string]struct {
		policyRefs        []PolicyIdReference
		providerResponses []policyprovider.PolicyResponse
		providerError     error
		expectedPolicies  []Policy
		expectedError     string
	}{
		"should return error when empty policy references list provided": {
			policyRefs:    []PolicyIdReference{},
			expectedError: "no policy references provided",
		},

		"should propagate policy provider error": {
			policyRefs: []PolicyIdReference{
				{ID: "policy1", Version: "1.0"},
				{ID: "policy2", Version: "1.0"},
			},
			providerError: errors.New("provider error"),
			expectedError: "failed to retrieve policies: provider error",
		},

		"should successfully convert provider responses to policies": {
			policyRefs: []PolicyIdReference{
				{ID: "policy1", Version: "1.0"},
				{ID: "policy2", Version: "1.0"},
			},
			providerResponses: []policyprovider.PolicyResponse{
				{
					ID:      "policy1",
					Version: "1.0",
					Content: []byte(`{"policy": "content1"}`),
				},
				{
					ID:      "policy2",
					Version: "1.0",
					Content: []byte(`{"policy": "content2"}`),
				},
			},
			expectedPolicies: []Policy{
				{
					ID:      "policy1",
					Version: "1.0",
					Content: []byte(`{"policy": "content1"}`),
				},
				{
					ID:      "policy2",
					Version: "1.0",
					Content: []byte(`{"policy": "content2"}`),
				},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Create mock provider
			mockProvider := new(mockPolicyProvider)
			mockEvaluator := new(mockPolicyEvaluator)

			// Configure provider mock if needed
			if len(tc.policyRefs) > 0 {
				var policyRequests []policyprovider.GetPolicyRequest
				for _, ref := range tc.policyRefs {
					policyRequests = append(policyRequests, policyprovider.GetPolicyRequest{
						ID:      ref.ID,
						Version: ref.Version,
					})
				}
				mockProvider.On("GetPolicies", mock.Anything, policyRequests).
					Return(tc.providerResponses, tc.providerError)
			}

			// Create decision maker
			dm := NewDecisionMaker(mockProvider, mockEvaluator).(*decisionMaker)

			// Call the private method via type assertion
			policies, err := dm.getPolicies(context.Background(), tc.policyRefs)

			// Verify results
			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedPolicies, policies)

			// Verify mock expectations
			mockProvider.AssertExpectations(t)
		})
	}
}

// Custom assertion helper to compare DecisionResponse objects with time tolerance
func assertResponseMatch(t *testing.T, expected, actual *DecisionResponse) {
	require.NotNil(t, actual, "actual response should not be nil")
	require.NotNil(t, expected, "expected response should not be nil")

	assert.Equal(t, expected.RequestID, actual.RequestID)
	assert.Equal(t, expected.Decision, actual.Decision)

	// Compare status
	if expected.Status != nil {
		require.NotNil(t, actual.Status)
		assert.Equal(t, expected.Status.Code, actual.Status.Code)
		assert.Equal(t, expected.Status.Message, actual.Status.Message)
	} else {
		assert.Nil(t, actual.Status)
	}

	// Compare obligations and advice
	assert.Equal(t, expected.Obligations, actual.Obligations)
	assert.Equal(t, expected.Advice, actual.Advice)

	// Check policy references (order might vary, so check length and contents)
	assert.Len(t, actual.PolicyIdReferences, len(expected.PolicyIdReferences))
	for _, expectedPolicy := range expected.PolicyIdReferences {
		found := false
		for _, actualPolicy := range actual.PolicyIdReferences {
			if expectedPolicy.ID == actualPolicy.ID && expectedPolicy.Version == actualPolicy.Version {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected policy reference %+v not found in actual response", expectedPolicy)
	}

	// Check that EvaluatedAt is recent (within last 5 seconds)
	assert.WithinDuration(t, time.Now(), actual.EvaluatedAt, 5*time.Second)
}

// TestDecision_UnmarshalJSON tests the Decision type's UnmarshalJSON method
func TestDecision_UnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		input         string
		expected      Decision
		expectedError string
	}{
		"should unmarshal valid Permit decision": {
			input:    `"Permit"`,
			expected: Permit,
		},
		"should unmarshal valid Deny decision": {
			input:    `"Deny"`,
			expected: Deny,
		},
		"should unmarshal valid Indeterminate decision": {
			input:    `"Indeterminate"`,
			expected: Indeterminate,
		},
		"should unmarshal valid NotApplicable decision": {
			input:    `"NotApplicable"`,
			expected: NotApplicable,
		},
		"should return error for invalid decision value": {
			input:         `"Invalid"`,
			expectedError: `invalid decision value: "Invalid", must be one of: Permit, Deny, Indeterminate, NotApplicable`,
		},
		"should return error for empty string": {
			input:         `""`,
			expectedError: "invalid decision value: \"\", must be one of: Permit, Deny, Indeterminate, NotApplicable",
		},
		"should return error for lowercase decision": {
			input:         `"permit"`,
			expectedError: `invalid decision value: "permit", must be one of: Permit, Deny, Indeterminate, NotApplicable`,
		},
		"should return error for mixed case decision": {
			input:         `"PERMIT"`,
			expectedError: `invalid decision value: "PERMIT", must be one of: Permit, Deny, Indeterminate, NotApplicable`,
		},
		"should return error for numeric input": {
			input:         `123`,
			expectedError: "json: cannot unmarshal number into Go value of type string",
		},
		"should return error for boolean input": {
			input:         `true`,
			expectedError: "json: cannot unmarshal bool into Go value of type string",
		},
		"should return error for object input": {
			input:         `{"decision": "Permit"}`,
			expectedError: "json: cannot unmarshal object into Go value of type string",
		},
		"should return error for array input": {
			input:         `["Permit"]`,
			expectedError: "json: cannot unmarshal array into Go value of type string",
		},
		"should return error for null input": {
			input:         `null`,
			expectedError: "invalid decision value: \"\", must be one of: Permit, Deny, Indeterminate, NotApplicable",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var decision Decision
			err := json.Unmarshal([]byte(tc.input), &decision)

			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, decision)
		})
	}
}

// TestStatusCode_UnmarshalJSON tests the StatusCode type's UnmarshalJSON method
func TestStatusCode_UnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		input         string
		expected      StatusCode
		expectedError string
	}{
		"should unmarshal valid StatusOK": {
			input:    `"OK"`,
			expected: StatusOK,
		},
		"should unmarshal valid StatusMissingAttribute": {
			input:    `"AttributeMissing"`,
			expected: StatusMissingAttribute,
		},
		"should unmarshal valid StatusProcessingError": {
			input:    `"ProcessingError"`,
			expected: StatusProcessingError,
		},
		"should unmarshal valid StatusEvaluationError": {
			input:    `"EvaluationError"`,
			expected: StatusEvaluationError,
		},
		"should unmarshal valid StatusPolicyNotFound": {
			input:    `"PolicyNotFound"`,
			expected: StatusPolicyNotFound,
		},
		"should return error for invalid status code": {
			input:         `"INVALID_STATUS"`,
			expectedError: "invalid status value: \"INVALID_STATUS\", must be one of: OK, AttributeMissing, ProcessingError, InvalidRequest, PolicyNotFound, EvaluationError",
		},
		"should return error for empty string": {
			input:         `""`,
			expectedError: "invalid status value: \"\", must be one of: OK, AttributeMissing, ProcessingError, InvalidRequest, PolicyNotFound, EvaluationError",
		},
		"should return error for lowercase status": {
			input:         `"ok"`,
			expectedError: "invalid status value: \"ok\", must be one of: OK, AttributeMissing, ProcessingError, InvalidRequest, PolicyNotFound, EvaluationError",
		},
		"should return error for mixed case status": {
			input:         `"Ok"`,
			expectedError: "invalid status value: \"Ok\", must be one of: OK, AttributeMissing, ProcessingError, InvalidRequest, PolicyNotFound, EvaluationError",
		},
		"should return error for numeric input": {
			input:         `200`,
			expectedError: "json: cannot unmarshal number into Go value of type string",
		},
		"should return error for boolean input": {
			input:         `false`,
			expectedError: "json: cannot unmarshal bool into Go value of type string",
		},
		"should return error for object input": {
			input:         `{"status": "OK"}`,
			expectedError: "json: cannot unmarshal object into Go value of type string",
		},
		"should return error for array input": {
			input:         `["OK"]`,
			expectedError: "json: cannot unmarshal array into Go value of type string",
		},
		"should return error for null input": {
			input:         `null`,
			expectedError: "invalid status value: \"\", must be one of: OK, AttributeMissing, ProcessingError, InvalidRequest, PolicyNotFound, EvaluationError",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var statusCode StatusCode
			err := json.Unmarshal([]byte(tc.input), &statusCode)

			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, statusCode)
			}
		})
	}
}
