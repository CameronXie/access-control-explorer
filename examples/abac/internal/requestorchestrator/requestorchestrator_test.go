package requestorchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CameronXie/access-control-explorer/abac/decisionmaker"
	"github.com/CameronXie/access-control-explorer/abac/infoprovider"
	ro "github.com/CameronXie/access-control-explorer/abac/requestorchestrator"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockInfoProvider struct {
	mock.Mock
}

func (m *mockInfoProvider) GetInfo(ctx context.Context, req *infoprovider.GetInfoRequest) (*infoprovider.GetInfoResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*infoprovider.GetInfoResponse), args.Error(1)
}

type mockDecisionMaker struct {
	mock.Mock
}

func (m *mockDecisionMaker) MakeDecision(ctx context.Context, req *decisionmaker.DecisionRequest) (*decisionmaker.DecisionResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*decisionmaker.DecisionResponse), args.Error(1)
}

type mockInfoAnalyser struct {
	mock.Mock
}

func (m *mockInfoAnalyser) AnalyseInfoRequirements(ctx context.Context, req *EnrichedAccessRequest) ([]infoprovider.GetInfoRequest, error) {
	args := m.Called(ctx, req)
	return args.Get(0).([]infoprovider.GetInfoRequest), args.Error(1)
}

func TestRequestOrchestrator_EvaluateAccess(t *testing.T) { //nolint:gocyclo // unit test
	testCases := map[string]struct {
		subjectInfoResp    *infoprovider.GetInfoResponse
		subjectInfoErr     error
		resourceInfoResp   *infoprovider.GetInfoResponse
		resourceInfoErr    error
		analyserReqs       []infoprovider.GetInfoRequest
		analyserErr        error
		additionalInfoResp map[string]*infoprovider.GetInfoResponse
		additionalInfoErr  map[string]error
		decisionResp       *decisionmaker.DecisionResponse
		decisionErr        error
		expectedResult     *ro.AccessResponse
		expectedError      string
	}{
		"should permit access when all info available": {
			subjectInfoResp: &infoprovider.GetInfoResponse{
				Info: map[string]any{"role": "admin"},
			},
			resourceInfoResp: &infoprovider.GetInfoResponse{
				Info: map[string]any{"owner": "user123"},
			},
			analyserReqs: []infoprovider.GetInfoRequest{},
			decisionResp: &decisionmaker.DecisionResponse{
				RequestID: uuid.New(),
				Decision:  decisionmaker.Permit,
				Status:    &decisionmaker.Status{Code: decisionmaker.StatusOK, Message: "OK"},
				PolicyIdReferences: []decisionmaker.PolicyIdReference{
					{ID: "policy1", Version: "v1"},
					{ID: "policy2", Version: "v2"},
				},
				EvaluatedAt: time.Now(),
			},
			expectedResult: &ro.AccessResponse{
				Decision: ro.Permit,
				Status:   ro.Status{Code: ro.StatusOK, Message: "OK"},
				PolicyIdReferences: []ro.PolicyIdReference{
					{ID: "policy1", Version: "v1"},
					{ID: "policy2", Version: "v2"},
				},
			},
		},

		"should return error when subject info not found": {
			subjectInfoErr: errors.New("user not found"),
			resourceInfoResp: &infoprovider.GetInfoResponse{
				Info: map[string]any{"owner": "user123"},
			},
			expectedError: "failed to enrich request: failed to get subject info: user not found",
		},

		"should return error when resource info not found": {
			subjectInfoResp: &infoprovider.GetInfoResponse{
				Info: map[string]any{"role": "admin"},
			},
			resourceInfoErr: errors.New("document not found"),
			expectedError:   "failed to enrich request: failed to get resource info: document not found",
		},

		"should return error when analyser fails": {
			subjectInfoResp:  &infoprovider.GetInfoResponse{Info: map[string]any{}},
			resourceInfoResp: &infoprovider.GetInfoResponse{Info: map[string]any{}},
			analyserErr:      errors.New("analysis failed"),
			expectedError:    "failed to analyze requirements: analyser failed: analysis failed",
		},

		"should return error when additional info unavailable": {
			subjectInfoResp:  &infoprovider.GetInfoResponse{Info: map[string]any{}},
			resourceInfoResp: &infoprovider.GetInfoResponse{Info: map[string]any{}},
			analyserReqs:     []infoprovider.GetInfoRequest{{InfoType: "metadata", Params: "extra"}},
			additionalInfoErr: map[string]error{
				"extra": errors.New("metadata unavailable"),
			},
			expectedError: "failed to get additional info: failed to get info for extra: metadata unavailable",
		},

		"should return error when decision maker fails": {
			subjectInfoResp:  &infoprovider.GetInfoResponse{Info: map[string]any{}},
			resourceInfoResp: &infoprovider.GetInfoResponse{Info: map[string]any{}},
			analyserReqs:     []infoprovider.GetInfoRequest{},
			decisionErr:      errors.New("decision failed"),
			expectedError:    "failed to make decision: decision failed",
		},

		"should deny access with obligations when policy requires": {
			subjectInfoResp:  &infoprovider.GetInfoResponse{Info: map[string]any{}},
			resourceInfoResp: &infoprovider.GetInfoResponse{Info: map[string]any{}},
			analyserReqs:     []infoprovider.GetInfoRequest{},
			decisionResp: &decisionmaker.DecisionResponse{
				RequestID: uuid.New(),
				Decision:  decisionmaker.Deny,
				Status:    &decisionmaker.Status{Code: decisionmaker.StatusOK, Message: "Access denied"},
				Obligations: []decisionmaker.Obligation{
					{ID: "log", Attributes: map[string]any{"action": "denied"}},
				},
				Advice: []decisionmaker.Advice{
					{ID: "contact", Attributes: map[string]any{"admin": "true"}},
				},
				EvaluatedAt: time.Now(),
				PolicyIdReferences: []decisionmaker.PolicyIdReference{
					{ID: "policy1", Version: "v1"},
				},
			},
			expectedResult: &ro.AccessResponse{
				Decision: ro.Deny,
				Status:   ro.Status{Code: ro.StatusOK, Message: "Access denied"},
				Obligations: []ro.Obligation{
					{ID: "log", Attributes: map[string]any{"action": "denied"}},
				},
				Advices: []ro.Advice{
					{ID: "contact", Attributes: map[string]any{"admin": "true"}},
				},
				PolicyIdReferences: []ro.PolicyIdReference{
					{ID: "policy1", Version: "v1"},
				},
			},
		},

		"should return error when duplicate info keys detected": {
			subjectInfoResp:  &infoprovider.GetInfoResponse{Info: map[string]any{}},
			resourceInfoResp: &infoprovider.GetInfoResponse{Info: map[string]any{}},
			analyserReqs: []infoprovider.GetInfoRequest{
				{InfoType: "metadata", Params: "extra1"},
				{InfoType: "metadata", Params: "extra2"},
			},
			additionalInfoResp: map[string]*infoprovider.GetInfoResponse{
				"extra1": {Info: map[string]any{"key": "value1"}},
				"extra2": {Info: map[string]any{"key": "value2"}},
			},
			expectedError: "failed to get additional info: duplicate info for key",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Setup fresh mocks for each test
			mockInfoProvider := new(mockInfoProvider)
			mockDecisionMaker := new(mockDecisionMaker)
			mockAnalyser := new(mockInfoAnalyser)

			testRequest := &ro.AccessRequest{
				Subject:  ro.Subject{ID: "user123", Type: "user"},
				Action:   ro.Action{ID: "read"},
				Resource: ro.Resource{ID: "doc456", Type: "document"},
			}

			// Setup subject info mock
			if tc.subjectInfoResp != nil || tc.subjectInfoErr != nil {
				mockInfoProvider.On("GetInfo", mock.Anything, &infoprovider.GetInfoRequest{
					InfoType: testRequest.Subject.Type,
					Params:   testRequest.Subject.ID,
				}).Return(tc.subjectInfoResp, tc.subjectInfoErr)
			}

			// Setup resource info mock
			if tc.resourceInfoResp != nil || tc.resourceInfoErr != nil {
				mockInfoProvider.On("GetInfo", mock.Anything, &infoprovider.GetInfoRequest{
					InfoType: testRequest.Resource.Type,
					Params:   testRequest.Resource.ID,
				}).Return(tc.resourceInfoResp, tc.resourceInfoErr)
			}

			// Setup analyser mock
			if tc.analyserReqs != nil || tc.analyserErr != nil {
				mockAnalyser.On("AnalyseInfoRequirements", mock.Anything, mock.Anything).Return(
					tc.analyserReqs, tc.analyserErr,
				)
			}

			// Setup additional info mocks
			if tc.additionalInfoResp != nil || tc.additionalInfoErr != nil {
				for id, resp := range tc.additionalInfoResp {
					err := tc.additionalInfoErr[id]
					mockInfoProvider.On("GetInfo", mock.Anything, &infoprovider.GetInfoRequest{
						InfoType: "metadata",
						Params:   id,
					}).Return(resp, err)
				}
				for id, err := range tc.additionalInfoErr {
					if tc.additionalInfoResp[id] == nil {
						mockInfoProvider.On("GetInfo", mock.Anything, &infoprovider.GetInfoRequest{
							InfoType: "metadata",
							Params:   id,
						}).Return((*infoprovider.GetInfoResponse)(nil), err)
					}
				}
			}

			// Setup decision maker mock
			if tc.decisionResp != nil || tc.decisionErr != nil {
				mockDecisionMaker.On("MakeDecision", mock.Anything, mock.Anything).Return(
					tc.decisionResp, tc.decisionErr,
				)
			}

			orchestrator := NewRequestOrchestrator(
				[]InfoAnalyser{mockAnalyser},
				mockInfoProvider,
				mockDecisionMaker,
			)

			result, err := orchestrator.EvaluateAccess(context.Background(), testRequest)

			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assertAccessResponse(t, tc.expectedResult, result)
			}

			mockInfoProvider.AssertExpectations(t)
			mockDecisionMaker.AssertExpectations(t)
			mockAnalyser.AssertExpectations(t)
		})
	}
}

func assertAccessResponse(t *testing.T, expected, actual *ro.AccessResponse) {
	assert.NotNil(t, actual)
	assert.NotNil(t, actual.RequestID)
	assert.False(t, actual.EvaluatedAt.IsZero())

	expected.RequestID = actual.RequestID
	expected.EvaluatedAt = actual.EvaluatedAt

	assert.EqualValues(t, expected, actual)
}
