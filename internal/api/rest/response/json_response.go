package response

import (
	"encoding/json"
	"net/http"
)

// JSONResponse writes the given data as a JSON response with the specified status code.
func JSONResponse(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

// JSONErrorResponse writes an error message as a JSON response with the specified status code.
func JSONErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	JSONResponse(w, statusCode, map[string]string{"error": message})
}
