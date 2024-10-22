package enforcer

import (
	"context"
	"strings"

	"github.com/CameronXie/access-control-explorer/internal/decisionmaker"
)

type Enforcer interface {
	Enforce(ctx context.Context, req *AccessRequest) (bool, error)
}

type AccessRequest struct {
	Subject  string
	Resource string
	Action   string
}

type enforcer struct {
	decisionMaker decisionmaker.DecisionMaker
}

func (e *enforcer) Enforce(ctx context.Context, req *AccessRequest) (bool, error) {
	return e.decisionMaker.MakeDecision(
		ctx,
		&decisionmaker.DecisionRequest{
			Subject:  strings.ToLower(req.Subject),
			Resource: strings.ToLower(req.Resource),
			Action:   strings.ToLower(req.Action),
		},
	)
}

func NewEnforcer(decisionMaker decisionmaker.DecisionMaker) Enforcer {
	return &enforcer{decisionMaker: decisionMaker}
}
