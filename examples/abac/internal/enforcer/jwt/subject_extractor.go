package jwt

import (
	"context"
	"errors"
	"net/http"

	ro "github.com/CameronXie/access-control-explorer/abac/requestorchestrator"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/api/rest/middleware"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/enforcer"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/infoprovider"
)

// subjectExtractor extracts subject information from context (set by JWT middleware)
type subjectExtractor struct{}

// NewSubjectExtractor creates a new subject extractor that reads from context
func NewSubjectExtractor() enforcer.SubjectExtractor {
	return &subjectExtractor{}
}

// Extract retrieves subject information from request context
func (*subjectExtractor) Extract(_ context.Context, r *http.Request) (*ro.Subject, error) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		return nil, errors.New("user ID not found in context")
	}

	return &ro.Subject{
		ID:   userID,
		Type: string(infoprovider.InfoTypeUser),
	}, nil
}
