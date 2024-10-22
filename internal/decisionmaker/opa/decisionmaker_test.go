package opa

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/CameronXie/access-control-explorer/internal/decisionmaker"
)

type MockPolicyRetriever struct {
	mock.Mock
}

func (m *MockPolicyRetriever) GetPolicy() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

type MockInfoProvider struct {
	mock.Mock
}

func (m *MockInfoProvider) GetRoles(id string) ([]string, error) {
	args := m.Called(id)
	return args.Get(0).([]string), args.Error(1)
}

func TestMakeDecision(t *testing.T) {
	policy := getPolicy()
	roles := []string{"admin"}

	cases := map[string]struct {
		mockPolicy string
		errPolicy  error
		mockRoles  []string
		errRoles   error
		expected   bool
		wantErr    string
	}{
		"Success": {
			mockPolicy: policy,
			errPolicy:  nil,
			mockRoles:  roles,
			errRoles:   nil,
			expected:   true,
		},
		"Policy retriever error": {
			mockPolicy: "",
			errPolicy:  errors.New("some error"),
			mockRoles:  roles,
			errRoles:   nil,
			expected:   false,
			wantErr:    "failed to get policy: some error",
		},
		"Query initialisation error": {
			mockPolicy: "",
			errPolicy:  nil,
			mockRoles:  roles,
			errRoles:   nil,
			expected:   false,
			wantErr:    "failed to prepare query: 1 error occurred: decisionmaker:0: rego_parse_error: empty module",
		},
		"Information provider error": {
			mockPolicy: policy,
			errPolicy:  nil,
			mockRoles:  nil,
			errRoles:   errors.New("some error"),
			expected:   false,
			wantErr:    "failed to get roles: some error",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			policyRetrieverMock := new(MockPolicyRetriever)
			infoProviderMock := new(MockInfoProvider)
			decisionMaker := NewDecisionMaker(policyRetrieverMock, infoProviderMock, "data.rbac.allow")
			request := &decisionmaker.DecisionRequest{
				Subject:  "testUser",
				Action:   "read",
				Resource: "database123",
			}

			policyRetrieverMock.On("GetPolicy").Return(tc.mockPolicy, tc.errPolicy)
			infoProviderMock.On("GetRoles", request.Subject).Return(tc.mockRoles, tc.errRoles)

			got, err := decisionMaker.MakeDecision(context.TODO(), request)

			if tc.wantErr != "" {
				assert.EqualError(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expected, got)
		})
	}
}

func getPolicy() string {
	return `
package rbac

role_permissions := {
    "admin": [{"action": "read",  "resource": "database123"}],
}

default allow = false

allow {
    # for each role in that list
    r := input.roles[_]
    # lookup the permissions list for role r
    permissions := role_permissions[r]
    # for each permission
    p := permissions[_]
    # check if the permission granted to r matches the user's request
    p == {"action": input.action, "resource": input.resource}
}
`
}
