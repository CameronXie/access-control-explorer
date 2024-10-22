package opa

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"

	"github.com/CameronXie/access-control-explorer/internal/decisionmaker"
	"github.com/CameronXie/access-control-explorer/internal/infoprovider"
	"github.com/CameronXie/access-control-explorer/internal/policyretriever"
)

const (
	moduleName = "decisionmaker"
)

type decisionMaker struct {
	policyRetriever policyretriever.PolicyRetriever
	infoProvider    infoprovider.InfoProvider
	query           string
}

// MakeDecision evaluates a policy against the given decision request and returns whether the action is allowed or not.
func (d *decisionMaker) MakeDecision(ctx context.Context, req *decisionmaker.DecisionRequest) (bool, error) {
	policy, err := d.policyRetriever.GetPolicy()
	if err != nil {
		return false, fmt.Errorf("failed to get policy: %w", err)
	}

	query, err := rego.New(rego.Module(moduleName, policy), rego.Query(d.query)).PrepareForEval(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to prepare query: %w", err)
	}

	roles, err := d.infoProvider.GetRoles(req.Subject)
	if err != nil {
		return false, fmt.Errorf("failed to get roles: %w", err)
	}

	result, err := query.Eval(ctx, rego.EvalInput(map[string]any{
		"roles":    roles,
		"action":   req.Action,
		"resource": req.Resource,
	}))

	if len(result) == 0 || result[0].Expressions[0] == nil || err != nil {
		return false, fmt.Errorf("failed to evaluate query: %w", err)
	}

	return result[0].Expressions[0].Value.(bool), nil
}

// NewDecisionMaker initializes a DecisionMaker with the provided PolicyRetriever, InfoProvider, and Rego query.
func NewDecisionMaker(
	policyRetriever policyretriever.PolicyRetriever,
	infoProvider infoprovider.InfoProvider,
	query string,
) decisionmaker.DecisionMaker {
	return &decisionMaker{
		policyRetriever: policyRetriever,
		infoProvider:    infoProvider,
		query:           query,
	}
}
