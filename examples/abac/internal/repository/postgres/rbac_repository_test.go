package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	ip "github.com/CameronXie/access-control-explorer/examples/abac/internal/infoprovider"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testRole struct {
	name string
}

type testAction struct {
	name string
}

type testResource struct {
	name string
}

type testRoleHierarchy struct {
	parentRole string
	childRole  string
}

type testRolePermission struct {
	roleName     string
	actionName   string
	resourceName string
	conditions   []testPermissionCondition
}

type testPermissionCondition struct {
	attributeKey   string
	operator       string
	attributeValue any
}

func TestRBACRepository_GetRoleDescendants(t *testing.T) {
	pool := setupTestDBForRBACRepo(t)
	defer pool.Close()
	repo := NewRBACRepository(pool)

	testCases := map[string]struct {
		rootRoles           []string
		testRoles           []testRole
		testRoleHierarchy   []testRoleHierarchy
		setupCtx            func() context.Context
		expectedDescendants []string
		expectedErrSubstr   string
	}{
		"should return descendants for single role with child": {
			rootRoles: []string{"manager"},
			testRoles: []testRole{
				{name: "manager"},
				{name: "employee"},
			},
			testRoleHierarchy: []testRoleHierarchy{
				{parentRole: "manager", childRole: "employee"},
			},
			setupCtx:            func() context.Context { return context.Background() },
			expectedDescendants: []string{"employee", "manager"},
		},
		"should return deduped descendants for multiple roots and deep tree": {
			rootRoles: []string{"admin", "lead"},
			testRoles: []testRole{
				{name: "admin"},
				{name: "lead"},
				{name: "engineer"},
			},
			testRoleHierarchy: []testRoleHierarchy{
				{parentRole: "admin", childRole: "lead"},
				{parentRole: "lead", childRole: "engineer"},
			},
			setupCtx:            func() context.Context { return context.Background() },
			expectedDescendants: []string{"admin", "engineer", "lead"},
		},
		"should return empty when role does not exist": {
			rootRoles:           []string{"ghost"},
			testRoles:           []testRole{},
			testRoleHierarchy:   []testRoleHierarchy{},
			setupCtx:            func() context.Context { return context.Background() },
			expectedDescendants: []string{},
		},
		"should return error when root roles is empty": {
			rootRoles:         []string{},
			testRoles:         []testRole{},
			testRoleHierarchy: []testRoleHierarchy{},
			setupCtx:          func() context.Context { return context.Background() },
			expectedErrSubstr: "rootRoles cannot be empty",
		},
		"should return error when context is cancelled": {
			rootRoles: []string{"manager"},
			testRoles: []testRole{
				{name: "manager"},
			},
			testRoleHierarchy: []testRoleHierarchy{},
			setupCtx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			expectedErrSubstr: "query role descendants",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			setupTestRBACRepoData(t, pool, tc.testRoles, nil, nil, tc.testRoleHierarchy, nil)

			ctx := tc.setupCtx()

			got, err := repo.GetRoleDescendants(ctx, tc.rootRoles)

			if tc.expectedErrSubstr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrSubstr)
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				assert.ElementsMatch(t, tc.expectedDescendants, got)
			}

			cleanupTestRBACRepoData(t, pool)
		})
	}
}

func TestRBACRepository_GetPermissionsByRoles(t *testing.T) {
	pool := setupTestDBForRBACRepo(t)
	defer pool.Close()
	repo := NewRBACRepository(pool)

	testCases := map[string]struct {
		roles             []string
		testRoles         []testRole
		testActions       []testAction
		testResources     []testResource
		testPermissions   []testRolePermission
		setupCtx          func() context.Context
		expected          map[string][]ip.Permission
		expectedErrSubstr string
	}{
		"should return permissions with and without conditions": {
			roles: []string{"manager", "employee"},
			testRoles: []testRole{
				{name: "manager"},
				{name: "employee"},
			},
			testActions: []testAction{
				{name: "read"},
				{name: "write"},
			},
			testResources: []testResource{
				{name: "document"},
				{name: "report"},
			},
			testPermissions: []testRolePermission{
				{
					roleName:     "manager",
					actionName:   "read",
					resourceName: "document",
					conditions: []testPermissionCondition{
						{attributeKey: "department", operator: "eq", attributeValue: "sales"},
					},
				},
				{
					roleName:     "manager",
					actionName:   "write",
					resourceName: "document",
					conditions: []testPermissionCondition{
						{attributeKey: "level", operator: "gte", attributeValue: float64(5)},
					},
				},
				{
					roleName:     "employee",
					actionName:   "read",
					resourceName: "report",
					conditions:   []testPermissionCondition{},
				},
			},
			setupCtx: func() context.Context { return context.Background() },
			expected: map[string][]ip.Permission{
				"manager": {
					{
						ActionName:   "read",
						ResourceName: "document",
						Conditions: []ip.PermissionCondition{
							{AttributeKey: "department", Operator: "eq", AttributeValue: "sales"},
						},
					},
					{
						ActionName:   "write",
						ResourceName: "document",
						Conditions: []ip.PermissionCondition{
							{AttributeKey: "level", Operator: "gte", AttributeValue: float64(5)},
						},
					},
				},
				"employee": {
					{
						ActionName:   "read",
						ResourceName: "report",
						Conditions:   []ip.PermissionCondition{},
					},
				},
			},
		},
		"should return empty when role has no permissions": {
			roles: []string{"viewer"},
			testRoles: []testRole{
				{name: "viewer"},
			},
			setupCtx: func() context.Context { return context.Background() },
			expected: map[string][]ip.Permission{},
		},
		"should return empty when input roles is empty": {
			roles:     []string{},
			testRoles: []testRole{},
			setupCtx:  func() context.Context { return context.Background() },
			expected:  map[string][]ip.Permission{},
		},
		"should return error when context is cancelled": {
			roles: []string{"manager"},
			testRoles: []testRole{
				{name: "manager"},
			},
			testActions:   []testAction{{name: "read"}},
			testResources: []testResource{{name: "doc"}},
			testPermissions: []testRolePermission{
				{roleName: "manager", actionName: "read", resourceName: "doc"},
			},
			setupCtx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			expectedErrSubstr: "query permissions for roles",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			setupTestRBACRepoData(t, pool, tc.testRoles, tc.testActions, tc.testResources, nil, tc.testPermissions)

			ctx := tc.setupCtx()
			got, err := repo.GetPermissionsByRoles(ctx, tc.roles)

			if tc.expectedErrSubstr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrSubstr)
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				// Compare role keys and permissions (order-independent)
				assert.Equal(t, len(tc.expected), len(got))
				for role, expectedPerms := range tc.expected {
					actual := got[role]
					assert.ElementsMatch(t, expectedPerms, actual, "permissions for role %s should match", role)
				}
			}

			cleanupTestRBACRepoData(t, pool)
		})
	}
}

func setupTestDBForRBACRepo(t *testing.T) *pgxpool.Pool {
	pg := fmt.Sprintf(
		"postgres://%s:%s@%s/%s?sslmode=%s",
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_HOST"),
		os.Getenv("POSTGRES_DB_TEST"),
		os.Getenv("POSTGRES_SSL"),
	)

	pool, err := pgxpool.New(context.Background(), pg)
	require.NoError(t, err)

	return pool
}

func setupTestRBACRepoData(
	t *testing.T,
	pool *pgxpool.Pool,
	roles []testRole,
	actions []testAction,
	resources []testResource,
	hierarchies []testRoleHierarchy,
	permissions []testRolePermission,
) {
	// Insert roles
	for _, role := range roles {
		_, err := pool.Exec(context.Background(), "INSERT INTO roles (id, name) VALUES ($1, $2)", uuid.New(), role.name)
		require.NoError(t, err)
	}

	// Insert actions
	for _, action := range actions {
		_, err := pool.Exec(context.Background(), "INSERT INTO actions (id, name) VALUES ($1, $2)", uuid.New(), action.name)
		require.NoError(t, err)
	}

	// Insert resources
	for _, resource := range resources {
		_, err := pool.Exec(context.Background(), "INSERT INTO resources (id, name) VALUES ($1, $2)", uuid.New(), resource.name)
		require.NoError(t, err)
	}

	// Insert role hierarchy
	for _, hierarchy := range hierarchies {
		_, err := pool.Exec(context.Background(), `
			INSERT INTO role_hierarchy (id, parent_role_id, child_role_id)
			SELECT $1, pr.id, cr.id
			FROM roles pr, roles cr
			WHERE pr.name = $2 AND cr.name = $3
		`, uuid.New(), hierarchy.parentRole, hierarchy.childRole)
		require.NoError(t, err)
	}

	// Insert role permissions and their conditions
	for _, permission := range permissions {
		permissionID := uuid.New()

		// Insert permission
		_, err := pool.Exec(context.Background(), `
			INSERT INTO role_permissions (id, role_id, action_id, resource_id)
			SELECT $1, r.id, a.id, res.id
			FROM roles r, actions a, resources res
			WHERE r.name = $2 AND a.name = $3 AND res.name = $4
		`, permissionID, permission.roleName, permission.actionName, permission.resourceName)
		require.NoError(t, err)

		// Insert permission conditions
		for _, condition := range permission.conditions {
			jsonValue, err := json.Marshal(condition.attributeValue)
			require.NoError(t, err)

			_, err = pool.Exec(context.Background(), `
				INSERT INTO role_permission_conditions (permission_id, attribute_key, operator, attribute_value)
				VALUES ($1, $2, $3, $4)
			`, permissionID, condition.attributeKey, condition.operator, jsonValue)
			require.NoError(t, err)
		}
	}
}

func cleanupTestRBACRepoData(t *testing.T, pool *pgxpool.Pool) {
	tables := []string{
		"role_permission_conditions",
		"role_permissions",
		"role_hierarchy",
		"resources",
		"actions",
		"roles",
	}

	for _, table := range tables {
		_, err := pool.Exec(context.Background(), fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table))
		require.NoError(t, err)
	}
}
