package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthcheckHandler(t *testing.T) {
	request, err := http.NewRequest("GET", "/health", nil)
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
}

func TestHealthcheckHandlerWithPOST(t *testing.T) {
	request, err := http.NewRequest("POST", "/health", nil)
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
}
