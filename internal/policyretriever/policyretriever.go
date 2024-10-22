package policyretriever

type PolicyRetriever interface {
	GetPolicy() (string, error)
}
