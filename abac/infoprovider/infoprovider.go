package infoprovider

import "context"

type GetInfoRequest struct {
	InfoType string
	Params   any
	Context  map[string]string
}

type GetInfoResponse struct {
	Info map[string]any
}

type InfoProvider interface {
	GetInfo(ctx context.Context, req *GetInfoRequest) (*GetInfoResponse, error)
}
