package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
				handleViolationReport(recorder, request)

				response := recorder.Result()
				defer response.Body.Close()

				if response.StatusCode != http.StatusMethodNotAllowed {
					t.Errorf("expected HTTP status %v; got %v", http.StatusMethodNotAllowed, response.StatusCode)
				}
			})
		}
	}
}

func TestHandlerForAllowingHealthcheck(t *testing.T) {
	request, err := http.NewRequest("GET", "/_healthcheck", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	recorder := httptest.NewRecorder()

	handleViolationReport(recorder, request)

	response := recorder.Result()
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP status %v; got %v", http.StatusOK, response.StatusCode)
	}
}

func TestFormattedOutputIncludesTimestamp(t *testing.T) {
	var rawReport = []byte(`{
		"csp-report": {
			"document-uri": "http://example.com/signup.html"
		}
	}`)

	var report CSPReport
	err := json.Unmarshal(rawReport, &report)
	if err != nil {
		fmt.Println("error:", err)
	}

	formattedReportOutput := formatReport(report)

	if !strings.Contains(formattedReportOutput, "timestamp=") {
		t.Errorf("timestamp key is expected but not found")
	}
}

func TestFormattedOutputIncludesEmptyKeysForRequiredValues(t *testing.T) {
	var rawReport = []byte(`{
		"csp-report": {
			"document-uri": "http://example.com/signup.html",
			"referrer": ""
		}
	}`)

	var report CSPReport
	err := json.Unmarshal(rawReport, &report)
	if err != nil {
		fmt.Println("error:", err)
	}

	formattedReportOutput := formatReport(report)

	if !strings.Contains(formattedReportOutput, "referrer=\"\"") {
		t.Errorf("expected to find empty 'referrer' value but did not")
	}
}

func TestValidateViolationWithInvalidBlockedURIs(t *testing.T) {
	invalidBlockedURIs := []string{
		"resource://",
		"chromenull://",
		"chrome-extension://",
		"safari-extension://",
		"mxjscall://",
		"webviewprogressproxy://",
		"res://",
		"mx://",
		"safari-resource://",
		"chromeinvoke://",
		"chromeinvokeimmediate://",
		"mbinit://",
		"opera://",
		"localhost",
		"127.0.0.1",
		"none://",
		"about:blank",
		"android-webview",
		"ms-browser-extension",
	}

	for _, blockedURI := range invalidBlockedURIs {
		// Makes the test name more readable for the output.
		testName := strings.Replace(blockedURI, "://", "", -1)

		t.Run(testName, func(t *testing.T) {
			var rawReport = []byte(fmt.Sprintf(`{
				"csp-report": {
					"blocked-uri": "%s"
				}
			}`, blockedURI))

			var report CSPReport
			jsonErr := json.Unmarshal(rawReport, &report)
			if jsonErr != nil {
				fmt.Println("error:", jsonErr)
			}

			validateErr := validateViolation(report)
			if validateErr == nil {
				t.Errorf("expected error to be raised but it didn't")
			}

			if validateErr.Error() != fmt.Sprintf("Blocked URI ('%s') is an invalid resource.", blockedURI) {
				t.Errorf("expected error to include correct message string but it didn't")
			}
		})
	}
}

func TestValidateViolationWithValidBlockedURIs(t *testing.T) {
	var rawReport = []byte(`{
		"csp-report": {
			"blocked-uri": "https://google.com/example.css"
		}
	}`)

	var report CSPReport
	jsonErr := json.Unmarshal(rawReport, &report)
	if jsonErr != nil {
		fmt.Println("error:", jsonErr)
	}

	validateErr := validateViolation(report)
	if validateErr != nil {
		t.Errorf("expected error not be raised")
	}
}
