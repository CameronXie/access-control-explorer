package requestorchestrator

import (
	"context"
	"fmt"
	"sync"

	"github.com/CameronXie/access-control-explorer/abac/decisionmaker"
	"github.com/CameronXie/access-control-explorer/abac/infoprovider"
	ro "github.com/CameronXie/access-control-explorer/abac/requestorchestrator"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
)

type Subject struct {
	ro.Subject
	Attributes map[string]any `json:"attributes,omitempty"`
}

type Resource struct {
	ro.Resource
	Attributes map[string]any `json:"attributes,omitempty"`
}

type EnrichedAccessRequest struct {
	Subject  Subject
	Action   ro.Action
	Resource Resource
}

type InfoAnalyser interface {
	AnalyseInfoRequirements(ctx context.Context, req *EnrichedAccessRequest) ([]infoprovider.GetInfoRequest, error)
}

type requestOrchestrator struct {
	infoAnalysers []InfoAnalyser
	infoProvider  infoprovider.InfoProvider
	decisionMaker decisionmaker.DecisionMaker
}

func NewRequestOrchestrator(
	infoAnalysers []InfoAnalyser,
	infoProvider infoprovider.InfoProvider,
	decisionMaker decisionmaker.DecisionMaker,
) ro.RequestOrchestrator {
	return &requestOrchestrator{
		infoAnalysers: infoAnalysers,
		infoProvider:  infoProvider,
		decisionMaker: decisionMaker,
	}
}

// EvaluateAccess processes an access request through enrichment, analysis, and decision-making
func (o *requestOrchestrator) EvaluateAccess(ctx context.Context, req *ro.AccessRequest) (*ro.AccessResponse, error) {
	enrichedReq, err := o.enrichAccessRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to enrich request: %w", err)
	}

	infoReqs, err := o.AnalyseInfoRequirements(ctx, enrichedReq)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze requirements: %w", err)
	}

	additionalInfo, err := o.getAdditionalInfo(ctx, infoReqs)
	if err != nil {
		return nil, fmt.Errorf("failed to get additional info: %w", err)
	}

	resp, err := o.decisionMaker.MakeDecision(ctx, createDecisionRequest(enrichedReq, additionalInfo))
	if err != nil {
		return nil, fmt.Errorf("failed to make decision: %w", err)
	}

	return toAccessResponse(resp), nil
}

// enrichAccessRequest fetches basic subject and resource attributes in parallel
func (o *requestOrchestrator) enrichAccessRequest(ctx context.Context, req *ro.AccessRequest) (*EnrichedAccessRequest, error) {
	enrichedReq := &EnrichedAccessRequest{
		Subject: Subject{
			Subject:    req.Subject,
			Attributes: make(map[string]any),
		},
		Action: req.Action,
		Resource: Resource{
			Resource:   req.Resource,
			Attributes: make(map[string]any),
		},
	}

	g, ctx := errgroup.WithContext(ctx)
	var mu sync.Mutex

	// Fetch subject attributes
	g.Go(func() error {
		resp, err := o.infoProvider.GetInfo(ctx, &infoprovider.GetInfoRequest{
			InfoType: req.Subject.Type,
			Params:   req.Subject.ID,
		})

		if err != nil {
			return fmt.Errorf("failed to get subject info: %w", err)
		}

		mu.Lock()
		enrichedReq.Subject.Attributes = resp.Info
		mu.Unlock()
		return nil
	})

	// Fetch resource attributes
	g.Go(func() error {
		resp, err := o.infoProvider.GetInfo(ctx, &infoprovider.GetInfoRequest{
			InfoType: req.Resource.Type,
			Params:   req.Resource.ID,
		})

		if err != nil {
			return fmt.Errorf("failed to get resource info: %w", err)
		}

		mu.Lock()
		enrichedReq.Resource.Attributes = resp.Info
		mu.Unlock()
		return nil
	})

	return enrichedReq, g.Wait()
}

// AnalyseInfoRequirements collects additional info requirements from all analyzers
func (o *requestOrchestrator) AnalyseInfoRequirements(
	ctx context.Context,
	req *EnrichedAccessRequest,
) ([]infoprovider.GetInfoRequest, error) {
	var results []infoprovider.GetInfoRequest

	for _, analyser := range o.infoAnalysers {
		reqs, err := analyser.AnalyseInfoRequirements(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("analyser failed: %w", err)
		}
		results = append(results, reqs...)
	}

	return results, nil
}

// getAdditionalInfo fetches additional info in parallel and returns a consolidated result
func (o *requestOrchestrator) getAdditionalInfo(ctx context.Context, infoReqs []infoprovider.GetInfoRequest) (map[string]any, error) {
	if len(infoReqs) == 0 {
		return make(map[string]any), nil
	}

	result := make(map[string]any)
	var mu sync.Mutex
	g, ctx := errgroup.WithContext(ctx)

	for idx := range infoReqs {
		req := infoReqs[idx]
		g.Go(func() error {
			resp, err := o.infoProvider.GetInfo(ctx, &req)
			if err != nil {
				return fmt.Errorf("failed to get info for %s: %w", req.Params, err)
			}

			mu.Lock()
			for k, v := range resp.Info {
				if _, ok := result[k]; ok {
					return fmt.Errorf("duplicate info for %s", k)
				}

				result[k] = v
			}
			mu.Unlock()
			return nil
		})
	}

	return result, g.Wait()
}

// createDecisionRequest converts enriched request to decision request format
func createDecisionRequest(req *EnrichedAccessRequest, additionalInfo map[string]any) *decisionmaker.DecisionRequest {
	return &decisionmaker.DecisionRequest{
		RequestID: uuid.New(),
		Subject: decisionmaker.Subject{
			ID:         req.Subject.ID,
			Type:       req.Subject.Type,
			Attributes: req.Subject.Attributes,
		},
		Action: decisionmaker.Action{
			ID: req.Action.ID,
		},
		Resource: decisionmaker.Resource{
			ID:         req.Resource.ID,
			Type:       req.Resource.Type,
			Attributes: req.Resource.Attributes,
		},
		Environment: additionalInfo,
	}
}

// toAccessResponse converts decision response to access response format
func toAccessResponse(resp *decisionmaker.DecisionResponse) *ro.AccessResponse {
	result := &ro.AccessResponse{
		RequestID: resp.RequestID,
		Decision:  ro.Decision(resp.Decision),
		Status: ro.Status{
			Code:    ro.StatusCode(resp.Status.Code),
			Message: resp.Status.Message,
		},
		EvaluatedAt:        resp.EvaluatedAt,
		PolicyIdReferences: make([]ro.PolicyIdReference, 0, len(resp.PolicyIdReferences)),
	}

	// Convert obligations if present
	if len(resp.Obligations) > 0 {
		result.Obligations = make([]ro.Obligation, len(resp.Obligations))
		for i, obligation := range resp.Obligations {
			result.Obligations[i] = ro.Obligation{
				ID:         obligation.ID,
				Attributes: obligation.Attributes,
			}
		}
	}

	// Convert advice if present
	if len(resp.Advice) > 0 {
		result.Advices = make([]ro.Advice, len(resp.Advice))
		for i, advice := range resp.Advice {
			result.Advices[i] = ro.Advice{
				ID:         advice.ID,
				Attributes: advice.Attributes,
			}
		}
	}

	for _, policyIdReference := range resp.PolicyIdReferences {
		result.PolicyIdReferences = append(result.PolicyIdReferences, ro.PolicyIdReference{
			ID:      policyIdReference.ID,
			Version: policyIdReference.Version,
		})
	}

	return result
}
