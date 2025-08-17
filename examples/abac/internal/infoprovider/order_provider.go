package infoprovider

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	ip "github.com/CameronXie/access-control-explorer/abac/infoprovider"
)

// OrderAttributesRepository defines the contract for order attribute operations
type OrderAttributesRepository interface {
	GetOrderAttributesByID(ctx context.Context, id uuid.UUID) (map[string]any, error)
}

// orderProvider implements InfoProvider for order data
type orderProvider struct {
	orderRepo OrderAttributesRepository
}

// NewOrderProvider creates a new order info provider with dependency injection
func NewOrderProvider(orderRepo OrderAttributesRepository) ip.InfoProvider {
	return &orderProvider{
		orderRepo: orderRepo,
	}
}

// GetInfo retrieves order attributes based on the provided request containing an order ID.
func (p *orderProvider) GetInfo(ctx context.Context, req *ip.GetInfoRequest) (*ip.GetInfoResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	orderIDStr, ok := req.Params.(string)
	if !ok {
		return nil, fmt.Errorf("order ID parameter must be a string, got %T: %v", req.Params, req.Params)
	}

	if orderIDStr == "" {
		return &ip.GetInfoResponse{Info: map[string]any{}}, nil
	}

	orderID, err := uuid.Parse(orderIDStr)
	if err != nil {
		return nil, fmt.Errorf("order ID must be a valid UUID format, got: %s", orderIDStr)
	}

	attrs, err := p.orderRepo.GetOrderAttributesByID(ctx, orderID)
	if err != nil {
		return nil, err
	}

	return &ip.GetInfoResponse{Info: attrs}, nil
}
