package infoprovider

import (
	"context"
	"fmt"
	"strings"

	ip "github.com/CameronXie/access-control-explorer/abac/infoprovider"
)

// Permission is a role permission with optional conditions.
type Permission struct {
	ActionName   string                `json:"action"`
	ResourceName string                `json:"resource"`
	Conditions   []PermissionCondition `json:"conditions,omitempty"`
}

// PermissionCondition is a conditional constraint on a permission.
type PermissionCondition struct {
	AttributeKey   string `json:"attribute_key"`
	Operator       string `json:"operator"`
	AttributeValue any    `json:"attribute_value"`
}

// RoleHierarchy contains requested roles and their descendants.
type RoleHierarchy struct {
	RequestedRoles []string `json:"requested_roles"`
	Descendants    []string `json:"descendants"`
}

// RBACRepository is the read-only contract this provider needs.
type RBACRepository interface {
	GetRoleDescendants(ctx context.Context, rootRoles []string) ([]string, error)
	GetPermissionsByRoles(ctx context.Context, roles []string) (map[string][]Permission, error)
}

type roleBasedAccessProvider struct {
	repo RBACRepository
}

// NewRoleBasedAccessProvider creates a storage-agnostic RBAC info provider.
func NewRoleBasedAccessProvider(repo RBACRepository) ip.InfoProvider {
	return &roleBasedAccessProvider{repo: repo}
}

// GetInfo retrieves role hierarchy and permissions for the provided roles.
func (p *roleBasedAccessProvider) GetInfo(ctx context.Context, req *ip.GetInfoRequest) (*ip.GetInfoResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	// Expecting []string in Params (can come as []any from JSON decode paths, normalize here).
	switch v := req.Params.(type) {
	case []string:
		return p.handle(ctx, v)
	case []any:
		roleNames := make([]string, 0, len(v))
		for _, r := range v {
			s, ok := r.(string)
			if !ok {
				return nil, fmt.Errorf("role names must be []string")
			}
			roleNames = append(roleNames, s)
		}
		return p.handle(ctx, roleNames)
	default:
		return nil, fmt.Errorf("role names parameter must be a []string, got %T", req.Params)
	}
}

func (p *roleBasedAccessProvider) handle(ctx context.Context, roleNames []string) (*ip.GetInfoResponse, error) {
	// Normalize and ensure non-empty
	normalized := make([]string, 0, len(roleNames))
	for _, r := range roleNames {
		if s := strings.TrimSpace(r); s != "" {
			normalized = append(normalized, s)
		}
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("at least one role name must be provided")
	}

	// Get all descendant roles (including the roots)
	descendants, err := p.repo.GetRoleDescendants(ctx, normalized)
	if err != nil {
		return nil, fmt.Errorf("failed to get role descendants for roles %v: %w", normalized, err)
	}
	if len(descendants) == 0 {
		return nil, fmt.Errorf("none of the requested roles were found: %v", normalized)
	}

	// Get permissions for all roles in the hierarchy
	perms, err := p.repo.GetPermissionsByRoles(ctx, descendants)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions for roles %v: %w", descendants, err)
	}

	return &ip.GetInfoResponse{
		Info: map[string]any{
			"role_hierarchy": RoleHierarchy{
				RequestedRoles: normalized,
				Descendants:    descendants,
			},
			"role_permissions": perms,
		},
	}, nil
}
