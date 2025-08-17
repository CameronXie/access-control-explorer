package trie

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testTrieEntry[T any] struct {
	paths []string
	value T
}

func TestNode_Insert(t *testing.T) {
	testCases := map[string]struct {
		trieEntries   []testTrieEntry[string]
		paths         []string
		value         string
		expectedError string
	}{

		"should insert multi-segment paths": {
			paths: []string{"api", "v1", "users"},
			value: "users-handler",
		},

		"should insert wildcard paths": {
			paths: []string{"api", "*", "status"},
			value: "status-handler",
		},

		"should insert multiple different paths": {
			trieEntries: []testTrieEntry[string]{
				{
					paths: []string{"api", "v1", "users"},
					value: "users-handler",
				},
			},
			paths: []string{"api", "v2"},
			value: "v2-handler",
		},

		"should return error for duplicate paths": {
			trieEntries: []testTrieEntry[string]{
				{
					paths: []string{"api", "users"},
					value: "existing-handler",
				},
			},
			paths:         []string{"api", "users"},
			value:         "new-handler",
			expectedError: "paths [api users] already exists",
		},

		"should insert root path successfully": {
			paths: []string{},
			value: "new-handler",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Setup
			root := New[string]()
			if len(tc.trieEntries) > 0 {
				for _, entry := range tc.trieEntries {
					require.NoError(t, root.Insert(entry.paths, entry.value))
				}
			}

			// Execute
			err := root.Insert(tc.paths, tc.value)

			// Assert
			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
				return
			}

			assert.NoError(t, err)

			// Verify insertion by searching
			if len(tc.paths) > 0 {
				node, searchErr := root.Search(tc.paths)
				assert.NoError(t, searchErr)
				assert.Equal(t, tc.value, node.Value)
				assert.True(t, node.IsEnd)
			} else {
				// For empty paths, check root node
				assert.Equal(t, tc.value, root.Value)
				assert.True(t, root.IsEnd)
			}
		})
	}
}

func TestNode_Search(t *testing.T) {
	testCases := map[string]struct {
		trieEntries   []testTrieEntry[string]
		paths         []string
		expectedValue string
		expectedError string
	}{
		"should find exact match multi-segment": {
			trieEntries: []testTrieEntry[string]{
				{
					paths: []string{"api", "v1", "users"},
					value: "users-handler",
				},
			},
			paths:         []string{"api", "v1", "users"},
			expectedValue: "users-handler",
		},

		"should find wildcard match": {
			trieEntries: []testTrieEntry[string]{
				{
					paths: []string{"api", "*", "status"},
					value: "status-handler",
				},
			},
			paths:         []string{"api", "v1", "status"},
			expectedValue: "status-handler",
		},

		"should prefer exact match over wildcard": {
			trieEntries: []testTrieEntry[string]{
				{
					paths: []string{"api", "*", "status"},
					value: "wildcard-handler",
				},
				{
					paths: []string{"api", "v1", "status"},
					value: "exact-handler",
				},
			},
			paths:         []string{"api", "v1", "status"},
			expectedValue: "exact-handler",
		},

		"should find root path successfully": {
			trieEntries: []testTrieEntry[string]{
				{
					paths: []string{},
					value: "root-handler",
				},
			},
			paths:         []string{},
			expectedValue: "root-handler",
		},

		"should return error for non-existent paths": {
			trieEntries: []testTrieEntry[string]{
				{
					paths: []string{"api", "v1"},
					value: "v1-handler",
				},
			},
			paths:         []string{"api", "v2"},
			expectedError: "no route found for key v2 in paths [api v2]",
		},

		"should return error for incomplete paths": {
			trieEntries: []testTrieEntry[string]{
				{
					paths: []string{"api", "v1", "users"},
					value: "users-handler",
				},
			},
			paths:         []string{"api", "v1"},
			expectedError: "paths [api v1] not found",
		},

		"should handle mixed exact and wildcard segments": {
			trieEntries: []testTrieEntry[string]{
				{
					paths: []string{"api", "*", "users", "*"},
					value: "mixed-handler",
				},
			},
			paths:         []string{"api", "v1", "users", "123"},
			expectedValue: "mixed-handler",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Setup
			root := New[string]()
			if len(tc.trieEntries) > 0 {
				for _, entry := range tc.trieEntries {
					require.NoError(t, root.Insert(entry.paths, entry.value))
				}
			}

			// Execute
			node, err := root.Search(tc.paths)

			// Assert
			if tc.expectedError != "" {
				assert.Contains(t, err.Error(), tc.expectedError)
				assert.Nil(t, node)
				return
			}

			assert.Nil(t, err)
			assert.NotNil(t, node)
			assert.Equal(t, tc.expectedValue, node.Value)
			assert.True(t, node.IsEnd)
		})
	}
}
