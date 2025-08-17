package filestore

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/CameronXie/access-control-explorer/abac/policyprovider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyProvider_GetPolicies(t *testing.T) {
	tempDir := setupTestDir(t)
	defer func() {
		require.NoError(t, os.RemoveAll(tempDir))
	}()

	testCases := map[string]struct {
		basePath       string
		requests       []policyprovider.GetPolicyRequest
		setupContext   func() context.Context
		expectedResult []policyprovider.PolicyResponse
		expectedError  string
	}{
		"should retrieve multiple policies successfully": {
			basePath: tempDir,
			requests: []policyprovider.GetPolicyRequest{
				{ID: "policy1", Version: "v1"},
				{ID: "policy2", Version: "v1"},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: []policyprovider.PolicyResponse{
				{ID: "policy1", Version: "v1", Content: []byte("policy1 content")},
				{ID: "policy2", Version: "v1", Content: []byte("policy2 content")},
			},
		},

		"should retrieve single policy successfully": {
			basePath: tempDir,
			requests: []policyprovider.GetPolicyRequest{
				{ID: "policy1", Version: "v2"},
			},
			setupContext: func() context.Context { return context.Background() },
			expectedResult: []policyprovider.PolicyResponse{
				{ID: "policy1", Version: "v2", Content: []byte("policy1 v2 content")},
			},
		},

		"should return error when policy does not exist": {
			basePath: tempDir,
			requests: []policyprovider.GetPolicyRequest{
				{ID: "nonexistent", Version: "v1"},
			},
			setupContext:  func() context.Context { return context.Background() },
			expectedError: "failed to get policy nonexistent@v1: policy not found",
		},

		"should return error when policy path is directory": {
			basePath: tempDir,
			requests: []policyprovider.GetPolicyRequest{
				{ID: "dir-policy", Version: "v1"},
			},
			setupContext:  func() context.Context { return context.Background() },
			expectedError: "failed to get policy dir-policy@v1: policy path is a directory, not a file",
		},

		"should return error when context is cancelled": {
			basePath: tempDir,
			requests: []policyprovider.GetPolicyRequest{
				{ID: "policy1", Version: "v1"},
			},
			setupContext: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			expectedError: "context canceled",
		},

		"should return error when base path does not exist": {
			basePath: "/nonexistent/path",
			requests: []policyprovider.GetPolicyRequest{
				{ID: "policy1", Version: "v1"},
			},
			setupContext:  func() context.Context { return context.Background() },
			expectedError: "failed to get policy policy1@v1: policy not found",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			provider := New(tc.basePath)

			// Setup context
			ctx := tc.setupContext()

			// Execute
			result, err := provider.GetPolicies(ctx, tc.requests)

			// Assert
			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.ElementsMatch(t, tc.expectedResult, result)
			}
		})
	}
}

func setupTestDir(t *testing.T) string {
	// Create a temporary test directory
	tempDir, err := os.MkdirTemp("", "policy-test")
	require.NoError(t, err)

	// Create version directories
	v1Dir := filepath.Join(tempDir, "v1")
	v2Dir := filepath.Join(tempDir, "v2")

	for _, dir := range []string{v1Dir, v2Dir} {
		require.NoError(t, os.MkdirAll(dir, 0755))
	}

	// Create policy files
	policies := map[string][]byte{
		filepath.Join(v1Dir, "policy1"): []byte("policy1 content"),
		filepath.Join(v1Dir, "policy2"): []byte("policy2 content"),
		filepath.Join(v2Dir, "policy1"): []byte("policy1 v2 content"),
	}

	for path, content := range policies {
		require.NoError(t, os.WriteFile(path, content, 0644)) //nolint:gosec // unit test
	}

	// Create a directory instead of a file to test error case
	dirPolicyPath := filepath.Join(v1Dir, "dir-policy")
	require.NoError(t, os.MkdirAll(dirPolicyPath, 0755))

	return tempDir
}
