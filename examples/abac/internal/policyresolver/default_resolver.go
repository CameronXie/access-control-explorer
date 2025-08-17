package policyresolver

import (
	"context"
	"errors"

	"github.com/CameronXie/access-control-explorer/abac/decisionmaker"
)

type defaultResolver struct {
	policyID      string
	policyVersion string
}

// NewDefaultResolver creates a new instance of defaultResolver with the specified policy ID and version.
func NewDefaultResolver(policyID, policyVersion string) decisionmaker.PolicyResolver {
	return &defaultResolver{
		policyID:      policyID,
		policyVersion: policyVersion,
	}
}

// Resolve resolves policy references by returning the configured default policy.
func (r *defaultResolver) Resolve(_ context.Context, req *decisionmaker.DecisionRequest) ([]decisionmaker.PolicyIdReference, error) {
	if req == nil {
		return nil, errors.New("decision request cannot be nil")
	}

	return []decisionmaker.PolicyIdReference{{
		ID:      r.policyID,
		Version: r.policyVersion,
	}}, nil
}
