package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

var invalidBlockedURIs = []string{
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
	"wvjbscheme://__wvjb_queue_message__",
	"nativebaiduhd://adblock",
	"bdvideo://error",
}

func TestValidateViolationWithInvalidBlockedURIs(t *testing.T) {
	for _, blockedURI := range invalidBlockedURIs {
		// Makes the test name more readable for the output.
		testName := strings.Replace(blockedURI, "://", "", -1)

		t.Run(testName, func(t *testing.T) {
			rawReport := []byte(fmt.Sprintf(`{
				"csp-report": {
					"document-uri": "https://example.com",
					"blocked-uri": "%s"
				}
			}`, blockedURI))

			var report CSPReport
			jsonErr := json.Unmarshal(rawReport, &report)
			if jsonErr != nil {
				fmt.Println("error:", jsonErr)
			}

			cspViolationHandler := &CSPViolationReportHandler{BlockedURIs: invalidBlockedURIs}
			validateErr := cspViolationHandler.validateViolation(report)
			if validateErr == nil {
				t.Errorf("expected error to be raised but it didn't")
			}

			if validateErr.Error() != fmt.Sprintf("blocked URI ('%s') is an invalid resource", blockedURI) {
				t.Errorf("expected error to include correct message string but it didn't")
			}
		})
	}
}

func TestValidateViolationWithValidBlockedURIs(t *testing.T) {
	rawReport := []byte(`{
		"csp-report": {
			"document-uri": "https://example.com",
			"blocked-uri": "https://google.com/example.css"
		}
	}`)

	var report CSPReport
	jsonErr := json.Unmarshal(rawReport, &report)
	if jsonErr != nil {
		fmt.Println("error:", jsonErr)
	}

	cspViolationHandler := &CSPViolationReportHandler{BlockedURIs: invalidBlockedURIs}
	validateErr := cspViolationHandler.validateViolation(report)
	if validateErr != nil {
		t.Errorf("expected error not be raised")
	}
}

func TestValidateNonHttpDocumentURI(t *testing.T) {
	log.SetOutput(io.Discard)

	report := CSPReport{Body: CSPReportBody{
		BlockedURI:  "http://example.com/",
		DocumentURI: "about",
	}}

	cspViolationHandler := &CSPViolationReportHandler{BlockedURIs: invalidBlockedURIs}
	validateErr := cspViolationHandler.validateViolation(report)
	if validateErr.Error() != "document URI ('about') is invalid" {
		t.Errorf("expected error to include correct message string but it didn't")
	}
}

func TestHandlerWithMetadata(t *testing.T) {
	csp := CSPReport{
		CSPReportBody{
			DocumentURI: "http://example.com",
			BlockedURI:  "http://example.com",
		},
	}

	payload, _ := json.Marshal(csp)

	for _, repeats := range []int{1, 2} {
		log := logrus.New()
		var logBuffer bytes.Buffer
		log.SetOutput(&logBuffer)

		url := "/?"
		for i := 0; i < repeats; i++ {
			url += fmt.Sprintf("metadata=value%d&", i)
		}

		request, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		recorder := httptest.NewRecorder()

		cspViolationHandler := &CSPViolationReportHandler{BlockedURIs: invalidBlockedURIs, Logger: log}
		cspViolationHandler.ServeHTTP(recorder, request)

		response := recorder.Result()
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			t.Errorf("expected HTTP status %v; got %v", http.StatusOK, response.StatusCode)
		}

		logOut := logBuffer.String()
		if !strings.Contains(logOut, "metadata=value0") {
			t.Fatalf("Logged result should contain metadata value0 in '%s'", logOut)
		}
		if strings.Contains(logOut, "metadata=value1") {
			t.Fatalf("Logged result shouldn't contain metadata value1 in '%s'", logOut)
		}
	}
}

func TestHandlerWithMetadataObject(t *testing.T) {
	csp := CSPReport{
		CSPReportBody{
			DocumentURI: "http://example.com",
			BlockedURI:  "http://example.com",
		},
	}

	payload, _ := json.Marshal(csp)

	log := logrus.New()
	var logBuffer bytes.Buffer
	log.SetOutput(&logBuffer)

	request, err := http.NewRequest("POST", "/path?a=b&c=d", bytes.NewBuffer(payload))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	recorder := httptest.NewRecorder()

	objectHandler := &CSPViolationReportHandler{Logger: log, MetadataObject: true}
	objectHandler.ServeHTTP(recorder, request)

	response := recorder.Result()
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP status %v; got %v", http.StatusOK, response.StatusCode)
	}

	logOut := logBuffer.String()
	if !strings.Contains(logOut, "metadata=\"map[a:b c:d]\"") {
		t.Fatalf("Logged result should contain metadata map '%s'", logOut)
	}
}

func TestHandleViolationReportMultipleTypeStatusCode(t *testing.T) {
	// Discard the output we create from the calls here.
	log.SetOutput(io.Discard)

	statusCodeValues := []interface{}{"200", 200}

	for _, statusCode := range statusCodeValues {
		t.Run(fmt.Sprintf("%T", statusCode), func(t *testing.T) {
			csp := CSPReport{
				CSPReportBody{
					DocumentURI: "https://example.com",
					StatusCode:  statusCode,
				},
			}

			payload, err := json.Marshal(csp)
			if err != nil {
				t.Fatalf("failed to marshal JSON: %v", err)
			}

			request, err := http.NewRequest("POST", "/", bytes.NewBuffer(payload))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			recorder := httptest.NewRecorder()
			cspViolationHandler := &CSPViolationReportHandler{BlockedURIs: invalidBlockedURIs, Logger: logrus.New()}
			cspViolationHandler.ServeHTTP(recorder, request)

			response := recorder.Result()
			defer response.Body.Close()

			if response.StatusCode != http.StatusOK {
				t.Errorf("expected HTTP status %v; got %v", http.StatusOK, response.StatusCode)
			}
		})
	}
}

func TestValidateViolationWithSourceFile(t *testing.T) {
	rawReport := []byte(`{
		"csp-report": {
			"document-uri": "https://example.com",
			"blocked-uri": "https://google.com/example.css",
			"column-number": 70774,
			"line-number": 2,
			"source-file": "https://example.com/example.js"
		}
	}`)

	var report CSPReport
	jsonErr := json.Unmarshal(rawReport, &report)
	if jsonErr != nil {
		t.Errorf("error: %s", jsonErr)
	}

	cspViolationHandler := &CSPViolationReportHandler{BlockedURIs: invalidBlockedURIs}
	validateErr := cspViolationHandler.validateViolation(report)
	if validateErr != nil {
		t.Errorf("Unexpected error raised")
	}
	if report.Body.SourceFile == "" {
		t.Errorf("Violation 'source-file' not found")
	}
	if report.Body.LineNumber == 0 {
		t.Errorf("Violation 'line-number' not found")
	}
	if report.Body.ColumnNumber == 0 {
		t.Errorf("Violation 'column-number' not found")
	}
}
