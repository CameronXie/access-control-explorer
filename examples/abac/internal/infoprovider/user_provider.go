package infoprovider

import (
	"context"
	"fmt"

	ip "github.com/CameronXie/access-control-explorer/abac/infoprovider"
	"github.com/google/uuid"
)

// UserAttributesRepository defines the contract for user attribute operations
type UserAttributesRepository interface {
	GetUserAttributesByID(ctx context.Context, id uuid.UUID) (map[string]any, error)
}

// userProvider implements InfoProvider for user data
type userProvider struct {
	userRepo UserAttributesRepository
}

// NewUserProvider creates a new user info provider with dependency injection
func NewUserProvider(userRepo UserAttributesRepository) ip.InfoProvider {
	return &userProvider{
		userRepo: userRepo,
	}
}

// GetInfo retrieves user attributes based on the provided request containing a user ID.
// Returns attributes with roles guaranteed to be []string type.
func (p *userProvider) GetInfo(ctx context.Context, req *ip.GetInfoRequest) (*ip.GetInfoResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	userIDStr, ok := req.Params.(string)
	if !ok {
		return nil, fmt.Errorf("user ID parameter must be a string, got %T: %v", req.Params, req.Params)
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, fmt.Errorf("user ID must be a valid UUID format, got: %s", userIDStr)
	}

	attrs, err := p.userRepo.GetUserAttributesByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &ip.GetInfoResponse{Info: attrs}, nil
}
