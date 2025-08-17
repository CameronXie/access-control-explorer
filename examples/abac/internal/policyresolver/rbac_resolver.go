package policyresolver

import (
	"context"
	"errors"

	"github.com/CameronXie/access-control-explorer/abac/decisionmaker"
)

type rbacResolver struct {
	policyID      string
	policyVersion string
}

// NewRBACResolver creates and returns a new instance of a PolicyResolver for handling RBAC policy resolution.
func NewRBACResolver(policyID, policyVersion string) decisionmaker.PolicyResolver {
	return &rbacResolver{
		policyID:      policyID,
		policyVersion: policyVersion,
	}
}

// Resolve checks if the subject has a "role" attribute and returns RBAC policy reference if found.
func (r *rbacResolver) Resolve(_ context.Context, req *decisionmaker.DecisionRequest) ([]decisionmaker.PolicyIdReference, error) {
	if req == nil {
		return nil, errors.New("decision request cannot be nil")
	}

	policyIdRefs := make([]decisionmaker.PolicyIdReference, 0)

	// Check if subject has role attribute
	if req.Subject.Attributes == nil {
		return policyIdRefs, nil
	}

	if _, hasRoles := req.Subject.Attributes["roles"]; !hasRoles {
		return policyIdRefs, nil
	}

	// Return RBAC policy reference
	return []decisionmaker.PolicyIdReference{{
		ID:      r.policyID,
		Version: r.policyVersion,
	}}, nil
}
