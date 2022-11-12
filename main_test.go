package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jacobbednarz/go-csp-collector/internal/handler"
	"github.com/jacobbednarz/go-csp-collector/internal/utils"
	"github.com/sirupsen/logrus"
)

var cspViolationReportHandler = &handler.CSPViolationReportHandler{
	BlockedURIs:                 utils.DefaultIgnoredBlockedURIs,
	TruncateQueryStringFragment: false,
	Logger:                      logrus.New(),
}

func TestHandlerForDisallowedMethods(t *testing.T) {
	disallowedMethods := []string{"GET", "DELETE", "PUT", "TRACE", "PATCH"}
	randomUrls := []string{"/", "/blah"}

	for _, method := range disallowedMethods {
		for _, url := range randomUrls {
			t.Run(method+url, func(t *testing.T) {
				request, err := http.NewRequest(method, url, nil)
				if err != nil {
					t.Fatalf("failed to create request: %v", err)
				}
				recorder := httptest.NewRecorder()

				cspViolationReportHandler.ServeHTTP(recorder, request)

				response := recorder.Result()
				defer response.Body.Close()

				if response.StatusCode != http.StatusMethodNotAllowed {
					t.Errorf("expected HTTP status %v; got %v", http.StatusMethodNotAllowed, response.StatusCode)
				}
			})
		}
	}
}
