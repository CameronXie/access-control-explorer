package opa

import "github.com/CameronXie/access-control-explorer/internal/policyretriever"

type hardcodedPolicyRetriever struct {
	policy string
}

// GetPolicy retrieves the hardcoded policy as a string and returns it along with any potential error.
func (p *hardcodedPolicyRetriever) GetPolicy() (string, error) {
	return p.policy, nil
}

// NewHardcodedPolicyRetriever creates a PolicyRetriever with a provided hardcoded policy string.
func NewHardcodedPolicyRetriever(policy string) policyretriever.PolicyRetriever {
	return &hardcodedPolicyRetriever{
		policy: policy,
	}
}
