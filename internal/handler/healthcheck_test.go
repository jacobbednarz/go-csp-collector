package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthcheckHandler(t *testing.T) {
	tests := []struct {
		method string
	}{
		{method: http.MethodGet},
		{method: http.MethodPost},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			request, err := http.NewRequest(tt.method, "/health", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			recorder := httptest.NewRecorder()

			HealthcheckHandler(recorder, request)

			response := recorder.Result()
			defer response.Body.Close()

			if response.StatusCode != http.StatusOK {
				t.Errorf("expected HTTP status %v; got %v", http.StatusOK, response.StatusCode)
			}
		})
	}
}
