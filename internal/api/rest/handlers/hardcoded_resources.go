package handlers

import (
	"net/http"

	"github.com/CameronXie/access-control-explorer/internal/api/rest/response"
)

// Resource represents a resource entity with an ID, name, and active status.
type Resource struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

// HardcodedResourcesHandler serves hardcoded resources via HTTP in JSON format.
type HardcodedResourcesHandler struct {
	resources []Resource
}

// ServeHTTP handles HTTP requests by responding with a JSON representation of the hardcoded resources.
func (h *HardcodedResourcesHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	response.JSONResponse(w, http.StatusOK, map[string]any{"data": h.resources})
}

// NewHardcodedResourcesHandler creates a new HTTP handler that serves a JSON representation of hardcoded resources.
func NewHardcodedResourcesHandler(resources []Resource) http.Handler {
	return &HardcodedResourcesHandler{
		resources: resources,
	}
}
