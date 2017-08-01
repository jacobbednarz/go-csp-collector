package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerForDisallowedMethodsOnRoot(t *testing.T) {
	disallowedMethods := []string{"GET", "DELETE", "PUT", "TRACE", "PATCH"}

	for _, method := range disallowedMethods {
		t.Run(method, func(t *testing.T) {
			request, err := http.NewRequest(method, "localhost:8080/", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			recorder := httptest.NewRecorder()
			handleViolationReport(recorder, request)

			response := recorder.Result()
			defer response.Body.Close()

			if response.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("Expected HTTP status %v; got %v", http.StatusMethodNotAllowed, response.Status)
			}
		})
	}
}
