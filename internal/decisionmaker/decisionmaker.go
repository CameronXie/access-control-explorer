package decisionmaker

import "context"

type DecisionRequest struct {
	Subject  string
	Resource string
	Action   string
}

type DecisionMaker interface {
	MakeDecision(ctx context.Context, req *DecisionRequest) (bool, error)
}
