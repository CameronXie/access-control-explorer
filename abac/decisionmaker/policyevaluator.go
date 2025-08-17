package decisionmaker

import (
	"context"
)

// EvaluationResult contains the output from the policy evaluation process
type EvaluationResult struct {
	Decision    Decision     `json:"decision"`
	Status      Status       `json:"status"`
	Obligations []Obligation `json:"obligations,omitempty"`
	Advice      []Advice     `json:"advice,omitempty"`
}

// PolicyEvaluator defines the interface for components that evaluate policies against decision requests to produce authorization decisions
type PolicyEvaluator interface {
	// Evaluate evaluates a decision request against a set of policies and returns an evaluation result or an error.
	Evaluate(ctx context.Context, req *DecisionRequest, policies []Policy) (*EvaluationResult, error)
}
