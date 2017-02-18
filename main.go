package main

import (
	"net/http"
)

func main() {
	http.HandleFunc("/", handleViolationReport)
	http.ListenAndServe(":80", nil)
}
func handleViolationReport(w http.ResponseWriter, r *http.Request) {
}
