package opa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/CameronXie/access-control-explorer/abac/decisionmaker"
	"github.com/open-policy-agent/opa/v1/rego"
)

// evaluator implements PolicyEvaluator using Open Policy Agent (OPA) Rego
type evaluator struct {
	query string
}

// NewEvaluator creates a PolicyEvaluator instance with the specified Rego query
func NewEvaluator(query string) decisionmaker.PolicyEvaluator {
	return &evaluator{
		query: query,
	}
}

// Evaluate executes policies against a decision request using OPA Rego engine
func (e *evaluator) Evaluate(
	ctx context.Context,
	req *decisionmaker.DecisionRequest,
	policies []decisionmaker.Policy,
) (*decisionmaker.EvaluationResult, error) {
	if req == nil {
		return nil, errors.New("decision request cannot be nil")
	}

	if len(policies) == 0 {
		return nil, errors.New("no policies provided for evaluation")
	}

	// Build Rego configuration
	regoArgs := []func(*rego.Rego){
		rego.Query(e.query),
		rego.Input(req),
	}

	// Add policies as Rego modules
	for _, policy := range policies {
		moduleName := fmt.Sprintf("policy_%s", policy.ID)
		regoArgs = append(regoArgs, rego.Module(moduleName, string(policy.Content)))
	}

	// Execute policy evaluation
	instance := rego.New(regoArgs...)
	resultSet, err := instance.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	if len(resultSet) == 0 || len(resultSet[0].Expressions) == 0 {
		return nil, errors.New("no evaluation results returned from policy engine")
	}

	// Convert result to EvaluationResult
	return convertResult(resultSet[0].Expressions[0].Value)
}

// convertResult transforms OPA evaluation output to EvaluationResult struct
func convertResult(value any) (*decisionmaker.EvaluationResult, error) {
	resultBytes, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal evaluation result: %w", err)
	}

	var result decisionmaker.EvaluationResult
	if err := json.Unmarshal(resultBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal evaluation result: %w", err)
	}

	return &result, nil
}
