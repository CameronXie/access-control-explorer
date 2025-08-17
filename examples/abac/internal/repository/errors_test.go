package repository

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNotFoundError_Error(t *testing.T) {
	testCases := map[string]struct {
		err      *NotFoundError
		expected string
	}{
		"should format error message with all fields": {
			err: &NotFoundError{
				Resource: "user",
				Key:      "email",
				Value:    "john.doe@example.com",
			},
			expected: "user with email john.doe@example.com not found",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			result := tc.err.Error()
			assert.Equal(t, tc.expected, result)
		})
	}
}
