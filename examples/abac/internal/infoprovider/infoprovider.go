package infoprovider

import (
	"context"
	"fmt"

	ip "github.com/CameronXie/access-control-explorer/abac/infoprovider"
)

// InfoType is the key under which a provider is registered.
type InfoType string

const (
	InfoTypeUser  InfoType = "user"
	InfoTypeOrder InfoType = "order"
	InfoTypeRBAC  InfoType = "rbac"
)

// infoProvider manages a collection of InfoProvider implementations mapped by type.
// It directs requests to the appropriate provider based on the request type.
type infoProvider struct {
	providers map[InfoType]ip.InfoProvider
}

// NewInfoProvider creates and returns an InfoProvider instance that routes requests based on their type using the given map.
func NewInfoProvider(providers map[InfoType]ip.InfoProvider) ip.InfoProvider {
	return &infoProvider{
		providers: providers,
	}
}

// GetInfo routes the request to the appropriate provider based on req.Type
func (p *infoProvider) GetInfo(ctx context.Context, req *ip.GetInfoRequest) (*ip.GetInfoResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	provider, ok := p.providers[InfoType(req.InfoType)]
	if !ok {
		return nil, fmt.Errorf("unsupported info type %s", req.InfoType)
	}

	return provider.GetInfo(ctx, req)
}
