package handler

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// WriteJSONResponse writes a JSON response with the given status code and data
func WriteJSONResponse(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

// WriteErrorResponse writes an error response with the given status code and message
func WriteErrorResponse(w http.ResponseWriter, statusCode int, err, message string) {
	response := ErrorResponse{
		Error:   err,
		Message: message,
	}
	WriteJSONResponse(w, statusCode, response)
}
