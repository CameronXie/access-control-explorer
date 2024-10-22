package casbin

import (
	"context"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"

	"github.com/CameronXie/access-control-explorer/internal/decisionmaker"
)

type decisionMaker struct {
	enforcer casbin.IEnforcer
}

// MakeDecision evaluates a decision request based on provided subject, resource, and action using the enforcer.
// It first loads the latest policy and then enforces the decision based on the request parameters.
// Returns a boolean indicating the enforcement result and an error if any occurs during policy loading or decision enforcement.
func (d *decisionMaker) MakeDecision(_ context.Context, req *decisionmaker.DecisionRequest) (bool, error) {
	err := d.enforcer.LoadPolicy()
	if err != nil {
		return false, err
	}

	return d.enforcer.Enforce(req.Subject, req.Resource, req.Action)
}

// NewDecisionMaker creates a new instance of DecisionMaker using the provided Casbin configuration and policy repository adapter.
// It returns a DecisionMaker for processing decision requests, or an error if model creation or enforcer initialization fails.
func NewDecisionMaker(config string, policyRepo persist.Adapter) (decisionmaker.DecisionMaker, error) {
	m, err := model.NewModelFromString(config)
	if err != nil {
		return nil, err
	}

	enforcer, err := casbin.NewEnforcer(m, policyRepo)
	if err != nil {
		return nil, err
	}

	return &decisionMaker{enforcer: enforcer}, nil
}
