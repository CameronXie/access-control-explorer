package infoprovider

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	ip "github.com/CameronXie/access-control-explorer/abac/infoprovider"
)

// mockRBACRepository is a mock implementation of RBACRepository
type mockRBACRepository struct {
	mock.Mock
}

func (m *mockRBACRepository) GetRoleDescendants(ctx context.Context, rootRoles []string) ([]string, error) {
	args := m.Called(ctx, rootRoles)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockRBACRepository) GetPermissionsByRoles(ctx context.Context, roles []string) (map[string][]Permission, error) {
	args := m.Called(ctx, roles)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string][]Permission), args.Error(1)
}

func TestNewRoleBasedAccessProvider(t *testing.T) {
	mockRepo := new(mockRBACRepository)
	provider := NewRoleBasedAccessProvider(mockRepo)

	assert.NotNil(t, provider)
	assert.IsType(t, &roleBasedAccessProvider{}, provider)
}

func TestRoleBasedAccessProvider_GetInfo(t *testing.T) {
	testCases := map[string]struct {
		request                  *ip.GetInfoRequest
		mockDescendantsResp      []string
		mockDescendantsErr       error
		mockPermissionsResp      map[string][]Permission
		mockPermissionsErr       error
		expectedResponse         *ip.GetInfoResponse
		expectedError            string
		shouldCallDescendants    bool
		shouldCallPermissions    bool
		expectedDescendantsParam []string
		expectedPermissionsParam []string
	}{
		"should handle complex permissions with multiple conditions": {
			request: &ip.GetInfoRequest{
				Params: []string{"security_admin"},
			},
			mockDescendantsResp: []string{"security_admin", "admin", "user"},
			mockPermissionsResp: map[string][]Permission{
				"security_admin": {
					{
						ActionName:   "access",
						ResourceName: "security_logs",
						Conditions: []PermissionCondition{
							{
								AttributeKey:   "clearance_level",
								Operator:       "gte",
								AttributeValue: "level5",
							},
							{
								AttributeKey:   "department",
								Operator:       "in",
								AttributeValue: []string{"security", "compliance"},
							},
						},
					},
					{
						ActionName:   "modify",
						ResourceName: "user_permissions",
						Conditions: []PermissionCondition{
							{
								AttributeKey:   "target_user_level",
								Operator:       "lt",
								AttributeValue: "admin",
							},
						},
					},
				},
			},
			expectedResponse: &ip.GetInfoResponse{
				Info: map[string]any{
					"role_hierarchy": RoleHierarchy{
						RequestedRoles: []string{"security_admin"},
						Descendants:    []string{"security_admin", "admin", "user"},
					},
					"role_permissions": map[string][]Permission{
						"security_admin": {
							{
								ActionName:   "access",
								ResourceName: "security_logs",
								Conditions: []PermissionCondition{
									{
										AttributeKey:   "clearance_level",
										Operator:       "gte",
										AttributeValue: "level5",
									},
									{
										AttributeKey:   "department",
										Operator:       "in",
										AttributeValue: []string{"security", "compliance"},
									},
								},
							},
							{
								ActionName:   "modify",
								ResourceName: "user_permissions",
								Conditions: []PermissionCondition{
									{
										AttributeKey:   "target_user_level",
										Operator:       "lt",
										AttributeValue: "admin",
									},
								},
							},
						},
					},
				},
			},
			shouldCallDescendants:    true,
			shouldCallPermissions:    true,
			expectedDescendantsParam: []string{"security_admin"},
			expectedPermissionsParam: []string{"security_admin", "admin", "user"},
		},

		"should handle []any params and convert to []string": {
			request: &ip.GetInfoRequest{
				Params: []any{"admin", "manager"},
			},
			mockDescendantsResp: []string{"admin", "manager", "user"},
			mockPermissionsResp: map[string][]Permission{
				"admin": {
					{
						ActionName:   "delete",
						ResourceName: "order",
						Conditions:   []PermissionCondition{},
					},
				},
			},
			expectedResponse: &ip.GetInfoResponse{
				Info: map[string]any{
					"role_hierarchy": RoleHierarchy{
						RequestedRoles: []string{"admin", "manager"},
						Descendants:    []string{"admin", "manager", "user"},
					},
					"role_permissions": map[string][]Permission{
						"admin": {
							{
								ActionName:   "delete",
								ResourceName: "order",
								Conditions:   []PermissionCondition{},
							},
						},
					},
				},
			},
			shouldCallDescendants:    true,
			shouldCallPermissions:    true,
			expectedDescendantsParam: []string{"admin", "manager"},
			expectedPermissionsParam: []string{"admin", "manager", "user"},
		},

		"should handle roles with whitespace by trimming": {
			request: &ip.GetInfoRequest{
				Params: []string{" admin ", "  manager  ", " user"},
			},
			mockDescendantsResp: []string{"admin", "manager", "user"},
			mockPermissionsResp: map[string][]Permission{},
			expectedResponse: &ip.GetInfoResponse{
				Info: map[string]any{
					"role_hierarchy": RoleHierarchy{
						RequestedRoles: []string{"admin", "manager", "user"},
						Descendants:    []string{"admin", "manager", "user"},
					},
					"role_permissions": map[string][]Permission{},
				},
			},
			shouldCallDescendants:    true,
			shouldCallPermissions:    true,
			expectedDescendantsParam: []string{"admin", "manager", "user"},
			expectedPermissionsParam: []string{"admin", "manager", "user"},
		},

		"should return error when request is nil": {
			request:               nil,
			expectedError:         "request cannot be nil",
			shouldCallDescendants: false,
			shouldCallPermissions: false,
		},

		"should return error when params is not []string or []any": {
			request: &ip.GetInfoRequest{
				Params: "invalid-params",
			},
			expectedError:         "role names parameter must be a []string, got string",
			shouldCallDescendants: false,
			shouldCallPermissions: false,
		},

		"should return error when []any contains non-string elements": {
			request: &ip.GetInfoRequest{
				Params: []any{"admin", 123, "user"},
			},
			expectedError:         "role names must be []string",
			shouldCallDescendants: false,
			shouldCallPermissions: false,
		},

		"should return error when all roles are empty after trimming": {
			request: &ip.GetInfoRequest{
				Params: []string{"", "  ", "\t\n"},
			},
			expectedError:         "at least one role name must be provided",
			shouldCallDescendants: false,
			shouldCallPermissions: false,
		},

		"should return error when no role descendants found": {
			request: &ip.GetInfoRequest{
				Params: []string{"nonexistent_role"},
			},
			mockDescendantsResp:      []string{},
			expectedError:            "none of the requested roles were found: [nonexistent_role]",
			shouldCallDescendants:    true,
			shouldCallPermissions:    false,
			expectedDescendantsParam: []string{"nonexistent_role"},
		},

		"should return error when GetRoleDescendants fails": {
			request: &ip.GetInfoRequest{
				Params: []string{"admin"},
			},
			mockDescendantsErr:       errors.New("database connection failed"),
			expectedError:            "failed to get role descendants for roles [admin]: database connection failed",
			shouldCallDescendants:    true,
			shouldCallPermissions:    false,
			expectedDescendantsParam: []string{"admin"},
		},

		"should return error when GetPermissionsByRoles fails": {
			request: &ip.GetInfoRequest{
				Params: []string{"admin"},
			},
			mockDescendantsResp:      []string{"admin", "user"},
			mockPermissionsErr:       errors.New("permission query failed"),
			expectedError:            "failed to get permissions for roles [admin user]: permission query failed",
			shouldCallDescendants:    true,
			shouldCallPermissions:    true,
			expectedDescendantsParam: []string{"admin"},
			expectedPermissionsParam: []string{"admin", "user"},
		},

		"should handle empty permissions map": {
			request: &ip.GetInfoRequest{
				Params: []string{"readonly_user"},
			},
			mockDescendantsResp: []string{"readonly_user"},
			mockPermissionsResp: map[string][]Permission{},
			expectedResponse: &ip.GetInfoResponse{
				Info: map[string]any{
					"role_hierarchy": RoleHierarchy{
						RequestedRoles: []string{"readonly_user"},
						Descendants:    []string{"readonly_user"},
					},
					"role_permissions": map[string][]Permission{},
				},
			},
			shouldCallDescendants:    true,
			shouldCallPermissions:    true,
			expectedDescendantsParam: []string{"readonly_user"},
			expectedPermissionsParam: []string{"readonly_user"},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Create mock repository
			mockRepo := new(mockRBACRepository)

			// Setup mocks in test case loop
			if tc.shouldCallDescendants {
				mockRepo.On("GetRoleDescendants", mock.Anything, tc.expectedDescendantsParam).Return(
					tc.mockDescendantsResp,
					tc.mockDescendantsErr,
				)
			}
			if tc.shouldCallPermissions {
				mockRepo.On("GetPermissionsByRoles", mock.Anything, tc.expectedPermissionsParam).Return(
					tc.mockPermissionsResp,
					tc.mockPermissionsErr,
				)
			}

			provider := NewRoleBasedAccessProvider(mockRepo)

			// Execute
			response, err := provider.GetInfo(context.Background(), tc.request)

			// Assert
			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				assert.EqualValues(t, tc.expectedResponse, response)
			}

			// Verify mock expectations
			mockRepo.AssertExpectations(t)
		})
	}
}
