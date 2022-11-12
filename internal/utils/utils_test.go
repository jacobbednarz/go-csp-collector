package utils_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jacobbednarz/go-csp-collector/internal/handler"
	"github.com/jacobbednarz/go-csp-collector/internal/utils"
	"github.com/sirupsen/logrus"
)

func TestFilterListProcessing(t *testing.T) {
	// Discard the output we create from the calls here.
	log.SetOutput(io.Discard)

	blockList := []string{
		"resource://",
		"",
		"# comment",
		"chrome-extension://",
		"",
	}
	trimmed := utils.TrimEmptyAndComments(blockList)

	if len(trimmed) != 2 {
		t.Errorf("expected filter list length 2; got %v", len(trimmed))
	}
	if trimmed[0] != "resource://" {
		t.Errorf("unexpected list entry; got %v", trimmed[0])
	}
	if trimmed[1] != "chrome-extension://" {
		t.Errorf("unexpected list entry; got %v", trimmed[1])
	}
}

func TestLogsPath(t *testing.T) {
	log := logrus.New()
	var logBuffer bytes.Buffer
	log.SetOutput(&logBuffer)

	csp := handler.CSPReport{
		Body: handler.CSPReportBody{
			DocumentURI: "http://example.com",
			BlockedURI:  "http://example.com",
		},
	}

	payload, _ := json.Marshal(csp)

	url := "/deep/link"

	request, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	recorder := httptest.NewRecorder()

	cspViolationHandler := &handler.CSPViolationReportHandler{BlockedURIs: []string{"foo"}, Logger: log}
	cspViolationHandler.ServeHTTP(recorder, request)

	response := recorder.Result()
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP status %v; got %v", http.StatusOK, response.StatusCode)
	}

	logOut := logBuffer.String()
	if !strings.Contains(logOut, "path=/deep/link") {
		t.Fatalf("Logged result should contain path value in '%s'", logOut)
	}
}

func TestTruncateQueryStringFragment(t *testing.T) {
	t.Parallel()

	cases := []struct {
		original string
		expected string
	}{
		{"http://localhost.com/?test#anchor", "http://localhost.com/"},
		{"http://example.invalid", "http://example.invalid"},
		{"http://example.invalid#a", "http://example.invalid"},
		{"http://example.invalid?a", "http://example.invalid"},
		{"http://example.invalid#b?a", "http://example.invalid"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.original, func(t *testing.T) {
			t.Parallel()
			actual := utils.TruncateQueryStringFragment(tc.original)
			if actual != tc.expected {
				t.Errorf("truncating '%s' yielded '%s', expected '%s'", tc.original, actual, tc.expected)
			}
		})
	}
}
