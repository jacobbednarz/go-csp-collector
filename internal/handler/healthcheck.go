package handler

import (
	"net/http"
)

// HealthcheckHandler answers liveness and readiness probes with an empty
// 200.
func HealthcheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
