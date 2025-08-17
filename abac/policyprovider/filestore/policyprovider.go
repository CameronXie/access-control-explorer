package filestore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CameronXie/access-control-explorer/abac/policyprovider"
)

// policyProvider implements the PolicyProvider interface using the local filesystem
type policyProvider struct {
	basePath string // Base directory where policies are stored
}

// New creates a new filesystem-based PolicyProvider
// The basePath parameter specifies the root directory for policy files
func New(basePath string) policyprovider.PolicyProvider {
	return &policyProvider{
		basePath: basePath,
	}
}

// GetPolicies retrieves multiple policies from the filesystem
func (p *policyProvider) GetPolicies(ctx context.Context, reqs []policyprovider.GetPolicyRequest) ([]policyprovider.PolicyResponse, error) {
	policies := make([]policyprovider.PolicyResponse, 0, len(reqs))

	for _, req := range reqs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			policy, err := p.getPolicy(req)
			if err != nil {
				return nil, fmt.Errorf("failed to get policy %s@%s: %w", req.ID, req.Version, err)
			}

			policies = append(policies, *policy)
		}
	}

	return policies, nil
}

// getPolicy retrieves a single policy from the filesystem
func (p *policyProvider) getPolicy(req policyprovider.GetPolicyRequest) (*policyprovider.PolicyResponse, error) {
	policyPath := filepath.Join(p.basePath, req.Version, req.ID)

	fileInfo, err := os.Stat(policyPath)
	if err != nil {
		return nil, fmt.Errorf("policy not found: %w", err)
	}

	if fileInfo.IsDir() {
		return nil, fmt.Errorf("policy path is a directory, not a file")
	}

	content, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy: %w", err)
	}

	return &policyprovider.PolicyResponse{
		ID:      req.ID,
		Version: req.Version,
		Content: content,
	}, nil
}
