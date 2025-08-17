package postgres

import (
	"context"
	"fmt"

	"github.com/CameronXie/access-control-explorer/examples/abac/internal/infoprovider"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RBACRepository provides Postgres-backed RBAC reads.
type RBACRepository struct {
	pool *pgxpool.Pool
}

// NewRBACRepository constructs a Postgres RBAC repository.
func NewRBACRepository(pool *pgxpool.Pool) *RBACRepository {
	return &RBACRepository{pool: pool}
}

// GetRoleDescendants retrieves all descendant roles (including the roots) via a recursive CTE.
func (r *RBACRepository) GetRoleDescendants(ctx context.Context, rootRoles []string) ([]string, error) {
	if len(rootRoles) == 0 {
		return nil, fmt.Errorf("rootRoles cannot be empty")
	}

	const query = `
WITH RECURSIVE role_descendants AS (
    -- Start with all root roles provided
    SELECT r.id,
           r.name,
           0 AS level
    FROM roles r
    WHERE r.name = ANY($1::text[])

    UNION ALL

    -- Add direct children
    SELECT child_role.id,
           child_role.name,
           rd.level + 1
    FROM role_hierarchy rh
    INNER JOIN roles child_role ON rh.child_role_id = child_role.id
    INNER JOIN role_descendants rd ON rh.parent_role_id = rd.id
)
SELECT DISTINCT name
FROM role_descendants
ORDER BY name;
`
	rows, err := r.pool.Query(ctx, query, rootRoles)
	if err != nil {
		return nil, fmt.Errorf("query role descendants for %v: %w", rootRoles, err)
	}
	defer rows.Close()

	var out []string
	var roleName string
	_, scanErr := pgx.ForEachRow(rows, []any{&roleName}, func() error {
		out = append(out, roleName)
		return nil
	})
	if scanErr != nil {
		return nil, fmt.Errorf("scan role descendants for %v: %w", rootRoles, scanErr)
	}
	return out, nil
}

// GetPermissionsByRoles retrieves permissions grouped by role for the given role names.
func (r *RBACRepository) GetPermissionsByRoles(ctx context.Context, roles []string) (map[string][]infoprovider.Permission, error) {
	if len(roles) == 0 {
		return map[string][]infoprovider.Permission{}, nil
	}

	const query = `
SELECT 
    r.name AS role_name,
    a.name AS action_name,
    res.name AS resource_name,
    rp.id AS permission_id,
    rpc.attribute_key,
    rpc.operator,
    rpc.attribute_value
FROM role_permissions rp
    INNER JOIN roles r ON rp.role_id = r.id
    INNER JOIN actions a ON rp.action_id = a.id
    INNER JOIN resources res ON rp.resource_id = res.id
    LEFT JOIN role_permission_conditions rpc ON rp.id = rpc.permission_id
WHERE r.name = ANY($1)
ORDER BY r.name, a.name, res.name, rpc.attribute_key
`
	rows, err := r.pool.Query(ctx, query, roles)
	if err != nil {
		return nil, fmt.Errorf("query permissions for roles %v: %w", roles, err)
	}
	defer rows.Close()

	return processPermissionRows(rows, roles)
}

// processPermissionRows converts DB rows into a role->[]Permission map.
func processPermissionRows(rows pgx.Rows, roles []string) (map[string][]infoprovider.Permission, error) {
	var roleName, actionName, resourceName, permissionID string
	var attributeKey, operator *string
	var attributeValue any

	type agg struct {
		role string
		perm infoprovider.Permission
	}

	byID := make(map[string]*agg)

	_, err := pgx.ForEachRow(
		rows,
		[]any{&roleName, &actionName, &resourceName, &permissionID, &attributeKey, &operator, &attributeValue},
		func() error {
			entry, ok := byID[permissionID]
			if !ok {
				entry = &agg{
					role: roleName,
					perm: infoprovider.Permission{
						ActionName:   actionName,
						ResourceName: resourceName,
						Conditions:   make([]infoprovider.PermissionCondition, 0),
					},
				}
				byID[permissionID] = entry
			}

			// Append condition row if present
			if attributeKey != nil && operator != nil {
				entry.perm.Conditions = append(entry.perm.Conditions, infoprovider.PermissionCondition{
					AttributeKey:   *attributeKey,
					Operator:       *operator,
					AttributeValue: attributeValue,
				})
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("process permissions for roles %v: %w", roles, err)
	}

	// Group by role
	out := make(map[string][]infoprovider.Permission)
	for _, entry := range byID {
		out[entry.role] = append(out[entry.role], entry.perm)
	}
	return out, nil
}
