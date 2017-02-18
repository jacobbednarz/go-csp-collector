package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type CSPReport struct {
	Body struct {
		DocumentURI        string `json:"document-uri"`
		Referrer           string `json:"referrer"`
		BlockedURI         string `json:"blocked-uri"`
		ViolatedDirective  string `json:"violated-directive"`
		EffectiveDirective string `json:"effective-directive"`
		OriginalPolicy     string `json:"original-policy"`
	} `json:"csp-report"`
}

func main() {
	http.HandleFunc("/", handleViolationReport)
	http.ListenAndServe(":80", nil)
}
func handleViolationReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var report CSPReport

	err := decoder.Decode(&report)
	if err != nil {
		panic(err)
	}
	defer r.Body.Close()


	reportData := formatReport(report)
	log.Println(reportData)
func formatReport(r CSPReport) string {
	s := []string{}

	s = append(s, fmt.Sprintf(`timestamp="%s"`, time.Now()))
	s = append(s, fmt.Sprintf(`document-uri="%s"`, r.Body.DocumentURI))
	s = append(s, fmt.Sprintf(`referrer="%s"`, r.Body.Referrer))
	s = append(s, fmt.Sprintf(`blocked-uri="%s"`, r.Body.BlockedURI))
	s = append(s, fmt.Sprintf(`violated-directive="%s"`, r.Body.ViolatedDirective))
	s = append(s, fmt.Sprintf(`effective-directive="%s"`, r.Body.EffectiveDirective))
	s = append(s, fmt.Sprintf(`original-policy="%s"`, r.Body.OriginalPolicy))

	return strings.Join(s, " ")
}
