package decisionmaker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/CameronXie/access-control-explorer/abac/policyprovider"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
)

// Decision represents the possible outcomes of an authorization decision
type Decision string

const (
	Permit        Decision = "Permit"        // Request is allowed
	Deny          Decision = "Deny"          // Request is denied
	Indeterminate Decision = "Indeterminate" // Errors prevented making a decision
	NotApplicable Decision = "NotApplicable" // No applicable policy was found
)

// UnmarshalJSON parses the JSON-encoded data and validates it as one of the defined Decision values.
func (d *Decision) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	switch Decision(s) {
	case Permit, Deny, Indeterminate, NotApplicable:
		*d = Decision(s)
		return nil
	default:
		return fmt.Errorf("invalid decision value: %q, must be one of: Permit, Deny, Indeterminate, NotApplicable", s)
	}
}

// StatusCode represents the possible states of the decision
type StatusCode string

const (
	StatusOK               StatusCode = "OK"               // Decision was successfully evaluated
	StatusMissingAttribute StatusCode = "AttributeMissing" // A required attribute is missing
	StatusProcessingError  StatusCode = "ProcessingError"  // An internal processing error occurred
	StatusInvalidRequest   StatusCode = "InvalidRequest"   // The request is malformed
	StatusPolicyNotFound   StatusCode = "PolicyNotFound"   // No matching policies were found
	StatusEvaluationError  StatusCode = "EvaluationError"  // General evaluation error
)

// UnmarshalJSON parses a JSON-encoded byte array and sets the StatusCode value if it matches a valid predefined status.
// Returns an error if the provided JSON does not represent a valid StatusCode.
func (sc *StatusCode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch StatusCode(s) {
	case StatusOK, StatusMissingAttribute, StatusProcessingError, StatusInvalidRequest, StatusPolicyNotFound, StatusEvaluationError:
		*sc = StatusCode(s)
		return nil
	default:
		return fmt.Errorf(
			"invalid status value: %q, must be one of: %s",
			s,
			strings.Join([]string{
				string(StatusOK),
				string(StatusMissingAttribute),
				string(StatusProcessingError),
				string(StatusInvalidRequest),
				string(StatusPolicyNotFound),
				string(StatusEvaluationError),
			}, ", "),
		)
	}
}

// Subject represents the entity requesting access (user, service, etc.)
type Subject struct {
	ID         string         `json:"id"`
	Type       string         `json:"type,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Resource represents the protected asset being accessed
type Resource struct {
	ID         string         `json:"id"`
	Type       string         `json:"type,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Action represents the operation being performed on the resource
type Action struct {
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// DecisionRequest represents an access decision request including the subject, resource, action, and environmental context.
type DecisionRequest struct {
	RequestID   uuid.UUID      `json:"requestId"`
	Subject     Subject        `json:"subject"`
	Resource    Resource       `json:"resource"`
	Action      Action         `json:"action"`
	Environment map[string]any `json:"environment,omitempty"`
}

// Obligation represents a mandatory action that must be performed when enforcing the decision
type Obligation struct {
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Advice represents a recommended but not mandatory action related to the decision
type Advice struct {
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Status provides detailed information about the outcome of the decision process
type Status struct {
	Code    StatusCode `json:"code"`
	Message string     `json:"message"`
}

// DecisionResponse represents the result of evaluating an authorization request, including decisions, status, and obligations.
type DecisionResponse struct {
	RequestID          uuid.UUID           `json:"requestId"`
	Decision           Decision            `json:"decision"`
	Status             *Status             `json:"status,omitempty"`
	Obligations        []Obligation        `json:"obligations,omitempty"`
	Advice             []Advice            `json:"advice,omitempty"`
	EvaluatedAt        time.Time           `json:"evaluatedAt"`
	PolicyIdReferences []PolicyIdReference `json:"policyIdReferences"`
}

// Policy represents a retrieved policy that will be evaluated against a request
type Policy struct {
	ID      string
	Version string
	Content []byte
}

// PolicyIdReference represents a reference to a policy, including its unique identifier and version information.
type PolicyIdReference struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// PolicyResolver defines the interface for components that resolve policy references based on a decision request.
type PolicyResolver interface {
	// Resolve analyzes a decision request and returns policy references that are applicable to the request.
	Resolve(ctx context.Context, req *DecisionRequest) ([]PolicyIdReference, error)
}

// DecisionMaker defines the interface for components that make authorization decisions
type DecisionMaker interface {
	// MakeDecision evaluates a decision request using policies and returns an authorization decision or an error.
	MakeDecision(ctx context.Context, req *DecisionRequest) (*DecisionResponse, error)
}

// decisionMaker implements the DecisionMaker interface
type decisionMaker struct {
	processors []PolicyResolver
	provider   policyprovider.PolicyProvider
	evaluator  PolicyEvaluator
}

// Option defines configuration options for DecisionMaker
type Option func(*decisionMaker)

// NewDecisionMaker creates a new DecisionMaker with the provided dependencies and options
func NewDecisionMaker(provider policyprovider.PolicyProvider, evaluator PolicyEvaluator, options ...Option) DecisionMaker {
	dm := &decisionMaker{
		processors: make([]PolicyResolver, 0),
		provider:   provider,
		evaluator:  evaluator,
	}

	for _, option := range options {
		option(dm)
	}

	return dm
}

// WithPolicyResolver registers a policy resolver
func WithPolicyResolver(processor PolicyResolver) Option {
	return func(dm *decisionMaker) {
		dm.processors = append(dm.processors, processor)
	}
}

// MakeDecision evaluates the given decision request based on applicable policies and returns a decision response or an error.
func (d *decisionMaker) MakeDecision(ctx context.Context, req *DecisionRequest) (*DecisionResponse, error) {
	if req == nil {
		return nil, errors.New("decision request cannot be nil")
	}

	// Resolve applicable policy references for this request
	policyRefs, err := d.resolve(ctx, req)
	if err != nil {
		return &DecisionResponse{
			RequestID: req.RequestID,
			Decision:  Indeterminate,
			Status: &Status{
				Code:    StatusProcessingError,
				Message: fmt.Sprintf("Failed to resolve policies: %v", err),
			},
			EvaluatedAt: time.Now(),
		}, nil
	}

	if len(policyRefs) == 0 {
		return &DecisionResponse{
			RequestID: req.RequestID,
			Decision:  NotApplicable,
			Status: &Status{
				Code:    StatusPolicyNotFound,
				Message: "No applicable policies found for the request",
			},
			EvaluatedAt: time.Now(),
		}, nil
	}

	// Retrieve policy contents
	policies, err := d.getPolicies(ctx, policyRefs)
	if err != nil {
		return &DecisionResponse{
			RequestID: req.RequestID,
			Decision:  Indeterminate,
			Status: &Status{
				Code:    StatusProcessingError,
				Message: fmt.Sprintf("Failed to retrieve policies: %v", err),
			},
			EvaluatedAt:        time.Now(),
			PolicyIdReferences: policyRefs,
		}, nil
	}

	// Evaluate the request against policies
	result, err := d.evaluator.Evaluate(ctx, req, policies)
	if err != nil {
		return &DecisionResponse{
			RequestID: req.RequestID,
			Decision:  Indeterminate,
			Status: &Status{
				Code:    StatusEvaluationError,
				Message: fmt.Sprintf("Policy evaluation failed: %v", err),
			},
			EvaluatedAt:        time.Now(),
			PolicyIdReferences: policyRefs,
		}, nil
	}

	// Build the final decision response with evaluation results, request metadata, and policy information
	response := &DecisionResponse{
		RequestID:          req.RequestID,
		Decision:           result.Decision,
		Status:             &result.Status,
		Obligations:        result.Obligations,
		Advice:             result.Advice,
		EvaluatedAt:        time.Now(),
		PolicyIdReferences: policyRefs,
	}

	return response, nil
}

// resolve executes the resolution process for a decision request using configured processors and returns unique policy references.
func (d *decisionMaker) resolve(ctx context.Context, req *DecisionRequest) ([]PolicyIdReference, error) {
	if len(d.processors) == 0 {
		return nil, errors.New("no policy resolve processors configured")
	}

	// Create an error group to manage parallel execution
	g, ctx := errgroup.WithContext(ctx)

	// Use mutex to protect the shared map
	var mu sync.Mutex
	seen := make(map[string]PolicyIdReference)

	// Launch each processor in its own goroutine
	for _, processor := range d.processors {
		proc := processor
		g.Go(func() error {
			// Check if context was canceled before processing
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Resolve the request
			results, err := proc.Resolve(ctx, req)
			if err != nil {
				return err
			}

			// Skip lock if no results
			if len(results) == 0 {
				return nil
			}

			// Safely add results to the shared map using policy ID as the key
			mu.Lock()
			defer mu.Unlock()
			for _, policyRef := range results {
				existingPolicyRef, exists := seen[policyRef.ID]

				if !exists {
					seen[policyRef.ID] = policyRef
					continue
				}

				if existingPolicyRef.Version == policyRef.Version {
					return fmt.Errorf(
						"duplicate policy reference detected: policy '%s' version '%s' returned by multiple processors",
						existingPolicyRef.ID,
						existingPolicyRef.Version,
					)
				}

				return fmt.Errorf("duplicate policy ID '%s' found: existing version '%s', conflicting version '%s'",
					policyRef.ID, existingPolicyRef.Version, policyRef.Version)
			}

			return nil
		})
	}

	// Wait for all processors to complete or first error
	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Convert the map values to a slice
	policyRefs := make([]PolicyIdReference, 0, len(seen))
	for _, policyRef := range seen {
		policyRefs = append(policyRefs, policyRef)
	}

	return policyRefs, nil
}

// getPolicies retrieves policy content for a list of policy references
func (d *decisionMaker) getPolicies(ctx context.Context, policyRefs []PolicyIdReference) ([]Policy, error) {
	if len(policyRefs) == 0 {
		return nil, errors.New("no policy references provided")
	}

	// Convert PolicyReference to PolicyRequests
	policyRequests := make([]policyprovider.GetPolicyRequest, 0, len(policyRefs))
	for _, ref := range policyRefs {
		policyRequests = append(policyRequests, policyprovider.GetPolicyRequest{
			ID:      ref.ID,
			Version: ref.Version,
		})
	}

	// Request policies from provider
	responses, err := d.provider.GetPolicies(ctx, policyRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve policies: %w", err)
	}

	// Resolve responses
	policies := make([]Policy, 0, len(responses))
	for _, resp := range responses {
		policies = append(policies, Policy{
			ID:      resp.ID,
			Version: resp.Version,
			Content: resp.Content,
		})
	}

	return policies, nil
}
