package casbin

import (
	"context"
	"testing"

	"github.com/casbin/casbin/v2"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/CameronXie/access-control-explorer/internal/decisionmaker"
)

const (
	policyPath = "testdata/policy.csv"
)

// mockEnforcer is a mock implementation of the casbin.IEnforcer interface used for testing purposes.
type mockEnforcer struct {
	casbin.IEnforcer
	mock.Mock
}

func (e *mockEnforcer) LoadPolicy() error {
	args := e.Called()
	return args.Error(0)
}

func (e *mockEnforcer) Enforce(rvals ...any) (bool, error) {
	args := e.Called(rvals...)
	return args.Bool(0), args.Error(1)
}

func TestDecisionMaker_MakeDecision(t *testing.T) {
	request := &decisionmaker.DecisionRequest{
		Resource: "resource",
		Action:   "action",
		Subject:  "subject",
	}

	enforcer := new(mockEnforcer)
	enforcer.On("LoadPolicy").Return(nil)
	enforcer.On(
		"Enforce",
		request.Subject, request.Resource, request.Action,
	).Return(true, nil)

	decisionMaker := decisionMaker{enforcer: enforcer}
	decision, err := decisionMaker.MakeDecision(context.TODO(), request)

	assert.True(t, decision)
	assert.NoError(t, err)
	enforcer.AssertCalled(t, "Enforce", request.Subject, request.Resource, request.Action)
	enforcer.AssertNumberOfCalls(t, "LoadPolicy", 1)
	enforcer.AssertNumberOfCalls(t, "Enforce", 1)
}

func TestNewDecisionMaker(t *testing.T) {
	d, err := NewDecisionMaker(getConfig(), fileadapter.NewAdapter(policyPath))
	assert.NoError(t, err)
	assert.NotNil(t, d)

	cases := map[string]struct {
		request        *decisionmaker.DecisionRequest
		expectDecision bool
		expectError    error
	}{
		"allow": {
			request: &decisionmaker.DecisionRequest{
				Subject:  "alice",
				Action:   "write",
				Resource: "data1",
			},
			expectDecision: true,
		},
		"deny": {
			request: &decisionmaker.DecisionRequest{
				Subject:  "bob",
				Action:   "write",
				Resource: "data1",
			},
			expectDecision: false,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			decision, err := d.MakeDecision(context.TODO(), tc.request)
			assert.Equal(t, tc.expectDecision, decision)
			assert.Equal(t, tc.expectError, err)
		})
	}
}

func getConfig() string {
	return `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`
}
