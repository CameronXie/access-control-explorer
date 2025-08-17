package infoanalyser

import (
	"context"
	"fmt"

	"github.com/CameronXie/access-control-explorer/abac/infoprovider"
	ip "github.com/CameronXie/access-control-explorer/examples/abac/internal/infoprovider"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/requestorchestrator"
)

type rbacAnalyser struct {
	infoType ip.InfoType
}

func NewRBACAnalyser(infoType ip.InfoType) requestorchestrator.InfoAnalyser {
	return &rbacAnalyser{
		infoType: infoType,
	}
}

func (a *rbacAnalyser) AnalyseInfoRequirements(
	_ context.Context,
	req *requestorchestrator.EnrichedAccessRequest,
) ([]infoprovider.GetInfoRequest, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	if req.Subject.Attributes == nil || req.Subject.Attributes["roles"] == nil {
		return nil, nil
	}

	return []infoprovider.GetInfoRequest{
		{
			InfoType: string(a.infoType),
			Params:   req.Subject.Attributes["roles"],
		},
	}, nil
}
