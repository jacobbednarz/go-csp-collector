package handler

import (
	"net/http"
)

func HealthcheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
