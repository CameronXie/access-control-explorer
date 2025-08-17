package policyprovider

import "context"

// GetPolicyRequest represents a request to retrieve a specific policy
type GetPolicyRequest struct {
	ID      string
	Version string
}

// PolicyResponse contains a policy's metadata and content
type PolicyResponse struct {
	ID      string
	Version string
	Content []byte
}

// PolicyProvider defines the interface for retrieving policies
type PolicyProvider interface {
	// GetPolicies retrieves multiple policies in a single call
	// Returns policy responses for each request or an error if retrieval fails
	GetPolicies(ctx context.Context, reqs []GetPolicyRequest) ([]PolicyResponse, error)
}
