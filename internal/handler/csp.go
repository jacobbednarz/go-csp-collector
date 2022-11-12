package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/jacobbednarz/go-csp-collector/internal/utils"
	log "github.com/sirupsen/logrus"
)

// CSPReport is the structure of the HTTP payload the system receives.
type CSPReport struct {
	Body CSPReportBody `json:"csp-report"`
}

// CSPReportBody contains the fields that are nested within the
// violation report.
type CSPReportBody struct {
	DocumentURI        string      `json:"document-uri"`
	Referrer           string      `json:"referrer"`
	BlockedURI         string      `json:"blocked-uri"`
	ViolatedDirective  string      `json:"violated-directive"`
	EffectiveDirective string      `json:"effective-directive"`
	OriginalPolicy     string      `json:"original-policy"`
	Disposition        string      `json:"disposition"`
	ScriptSample       string      `json:"script-sample"`
	StatusCode         interface{} `json:"status-code"`
}

type CSPViolationReportHandler struct {
	ReportOnly                  bool
	TruncateQueryStringFragment bool
	BlockedURIs                 []string

	LogClientIP          bool
	LogTruncatedClientIP bool
	MetadataObject       bool

	Logger *log.Logger
}

func (vrh *CSPViolationReportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var report CSPReport

	err := decoder.Decode(&report)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		vrh.Logger.Debugf("unable to decode invalid JSON payload: %s", err)
		return
	}

	defer r.Body.Close()

	reportValidation := vrh.validateViolation(report)
	if reportValidation != nil {
		http.Error(w, reportValidation.Error(), http.StatusBadRequest)
		vrh.Logger.Debugf("received invalid payload: %s", reportValidation.Error())
		return
	}

	var metadata interface{}
	if vrh.MetadataObject {
		metadataMap := make(map[string]string)
		query := r.URL.Query()

		for k, v := range query {
			metadataMap[k] = v[0]
		}

		metadata = metadataMap
	} else {
		metadatas, gotMetadata := r.URL.Query()["metadata"]
		if gotMetadata {
			metadata = metadatas[0]
		}
	}

	lf := log.Fields{
		"report_only":         vrh.ReportOnly,
		"document_uri":        report.Body.DocumentURI,
		"referrer":            report.Body.Referrer,
		"blocked_uri":         report.Body.BlockedURI,
		"violated_directive":  report.Body.ViolatedDirective,
		"effective_directive": report.Body.EffectiveDirective,
		"original_policy":     report.Body.OriginalPolicy,
		"disposition":         report.Body.Disposition,
		"script_sample":       report.Body.ScriptSample,
		"status_code":         report.Body.StatusCode,
		"metadata":            metadata,
		"path":                r.URL.Path,
	}

	if vrh.TruncateQueryStringFragment {
		lf["document_uri"] = utils.TruncateQueryStringFragment(report.Body.DocumentURI)
		lf["referrer"] = utils.TruncateQueryStringFragment(report.Body.Referrer)
		lf["blocked_uri"] = utils.TruncateQueryStringFragment(report.Body.BlockedURI)
	}

	if vrh.LogClientIP {
		ip, err := utils.GetClientIP(r)
		if err != nil {
			vrh.Logger.Warnf("unable to parse client ip: %s", err)
		}
		lf["client_ip"] = ip.String()
	}

	if vrh.LogTruncatedClientIP {
		ip, err := utils.GetClientIP(r)
		if err != nil {
			vrh.Logger.Warnf("unable to parse client ip: %s", err)
		}
		lf["client_ip"] = utils.TruncateClientIP(ip)
	}

	vrh.Logger.WithFields(lf).Info()
}

func (vrh *CSPViolationReportHandler) validateViolation(r CSPReport) error {
	for _, value := range vrh.BlockedURIs {
		if strings.HasPrefix(r.Body.BlockedURI, value) {
			err := fmt.Errorf("blocked URI ('%s') is an invalid resource", value)
			return err
		}
	}

	if !strings.HasPrefix(r.Body.DocumentURI, "http") {
		return fmt.Errorf("document URI ('%s') is invalid", r.Body.DocumentURI)
	}

	return nil
}
