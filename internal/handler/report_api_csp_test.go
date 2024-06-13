package handler

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestReportAPICspReport(t *testing.T) {
	rawReport := []byte(`[
    {
        "age": 156165,
        "body": {
            "blockedURL": "inline",
            "disposition": "report",
            "documentURL": "https://integrations.miro.com/asana-cards/miro-plugin.html",
            "effectiveDirective": "script-src-elem",
            "lineNumber": 1,
            "originalPolicy": "default-src 'self'; script-src 'self'; report-to csp-endpoint2;",
            "referrer": "https://miro.com/",
            "sample": "",
            "sourceFile": "https://integrations.miro.com/asana-cards/miro-plugin.html",
            "statusCode": 200
        },
        "type": "csp-violation",
        "url": "https://integrations.miro.com/asana-cards/miro-plugin.html",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    },
    {
        "age": 156165,
        "body": {
            "blockedURL": "https://static.miro-apps.com/integrations/asana-addon/js/miro-plugin.a8cdc6de401c0d820778.js",
            "disposition": "report",
            "documentURL": "https://integrations.miro.com/asana-cards/miro-plugin.html",
            "effectiveDirective": "script-src-elem",
            "originalPolicy": "default-src 'self'; script-src 'self'; report-to csp-endpoint2;",
            "referrer": "https://miro.com/",
            "sample": "",
            "statusCode": 200
        },
        "type": "csp-violation",
        "url": "https://integrations.miro.com/asana-cards/miro-plugin.html",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    },
    {
        "age": 156165,
        "body": {
            "blockedURL": "https://miro.com/app/static/sdk.1.1.js",
            "disposition": "report",
            "documentURL": "https://integrations.miro.com/asana-cards/miro-plugin.html",
            "effectiveDirective": "script-src-elem",
            "originalPolicy": "default-src 'self'; script-src 'self'; report-to csp-endpoint2;",
            "referrer": "https://miro.com/",
            "sample": "",
            "statusCode": 200
        },
        "type": "csp-violation",
        "url": "https://integrations.miro.com/asana-cards/miro-plugin.html",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    }
]`)

	var reports_raw []ReportAPIReport
	jsonErr := json.Unmarshal(rawReport, &reports_raw)
	if jsonErr != nil {
		fmt.Println("error:", jsonErr)
	}

	reports := ReportAPIReports{
		Reports: reports_raw,
	}

	reportApiViolationHandler := &ReportAPIViolationReportHandler{BlockedURIs: invalidBlockedURIs}
	validateErr := reportApiViolationHandler.validateViolation(reports)
	if validateErr != nil {
		t.Errorf("expected error not be raised")
	}
}
