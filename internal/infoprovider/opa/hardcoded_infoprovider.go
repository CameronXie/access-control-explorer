package opa

import (
	"fmt"

	"github.com/CameronXie/access-control-explorer/internal/infoprovider"
)

type hardcodedInfoProvider struct {
	users map[string][]string
}

// GetRoles returns a slice of roles for a given user ID.
// It returns an error if the user ID is not found.
func (p *hardcodedInfoProvider) GetRoles(id string) ([]string, error) {
	if roles, ok := p.users[id]; ok {
		return roles, nil
	}

	return nil, fmt.Errorf("user %s not found", id)
}

// NewHardcodedInfoProvider initializes a new InfoProvider with a map of users and their corresponding roles.
func NewHardcodedInfoProvider(users map[string][]string) infoprovider.InfoProvider {
	return &hardcodedInfoProvider{users: users}
}
