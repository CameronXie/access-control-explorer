package requestorchestrator

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Decision string

const (
	Permit        Decision = "Permit"        // Request is allowed
	Deny          Decision = "Deny"          // Request is denied
	Indeterminate Decision = "Indeterminate" // Errors prevented making a decision
	NotApplicable Decision = "NotApplicable" // No applicable policy was found
)

type StatusCode string

const (
	StatusOK               StatusCode = "OK"               // Decision was successfully evaluated
	StatusMissingAttribute StatusCode = "AttributeMissing" // A required attribute is missing
	StatusProcessingError  StatusCode = "ProcessingError"  // An internal processing error occurred
	StatusInvalidRequest   StatusCode = "InvalidRequest"   // The request is malformed
	StatusPolicyNotFound   StatusCode = "PolicyNotFound"   // No matching policies were found
	StatusEvaluationError  StatusCode = "EvaluationError"  // General evaluation error
)

type Subject struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type Action struct {
	ID string `json:"id"`
}

type Resource struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type AccessRequest struct {
	Subject  Subject  `json:"subject"`
	Action   Action   `json:"action"`
	Resource Resource `json:"resource"`
}

type Obligation struct {
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

type Advice struct {
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

type Status struct {
	Code    StatusCode `json:"code"`
	Message string     `json:"message"`
}

type PolicyIdReference struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type AccessResponse struct {
	RequestID          uuid.UUID           `json:"requestId"`
	Decision           Decision            `json:"decision"`
	Status             Status              `json:"status"`
	Obligations        []Obligation        `json:"obligations,omitempty"`
	Advices            []Advice            `json:"advices,omitempty"`
	EvaluatedAt        time.Time           `json:"evaluatedAt"`
	PolicyIdReferences []PolicyIdReference `json:"policyIdReferences"`
}

type RequestOrchestrator interface {
	EvaluateAccess(ctx context.Context, req *AccessRequest) (*AccessResponse, error)
}
