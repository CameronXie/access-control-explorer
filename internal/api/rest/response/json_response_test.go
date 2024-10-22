package response

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJSONResponse(t *testing.T) {
	cases := map[string]struct {
		status   int
		data     any
		expected string
	}{
		"Struct": {http.StatusOK, struct{ Name string }{Name: "test"}, `{"Name":"test"}`},
		"String": {http.StatusOK, "test", `"test"`},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			JSONResponse(rr, tc.status, tc.data)
			checkResponse(t, rr, tc.status, tc.expected)
		})
	}
}

func TestJSONErrorResponse(t *testing.T) {
	cases := map[string]struct {
		status   int
		message  string
		expected string
	}{
		"Valid":    {http.StatusOK, "test data", `{"error":"test data"}`},
		"NotFound": {http.StatusNotFound, "not found", `{"error":"not found"}`},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			JSONErrorResponse(rr, tc.status, tc.message)
			checkResponse(t, rr, tc.status, tc.expected)
		})
	}
}

func checkResponse(t *testing.T, rr *httptest.ResponseRecorder, expectedStatus int, expectedBody string) {
	result := rr.Result()
	defer result.Body.Close()

	body, _ := io.ReadAll(result.Body)

	if result.StatusCode != expectedStatus {
		t.Errorf("Expected response code %v. Got %v", expectedStatus, result.StatusCode)
	}
	if string(body) != expectedBody+"\n" {
		t.Errorf("Expected response %s. Got %s", expectedBody, string(body))
	}
}
