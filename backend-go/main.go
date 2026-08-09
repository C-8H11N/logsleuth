package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

const maxUpload = int64(2 << 30)

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" || strings.HasPrefix(origin, "http://localhost:") || strings.HasPrefix(origin, "http://127.0.0.1:") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		} else {
			writeJSON(w, 403, map[string]string{"error": "origin not allowed"})
			return
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok", "engine": "LogSleuth Go", "version": "0.4.0"})
	})
	mux.HandleFunc("POST /api/v1/analyze/log", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid or oversized upload"})
			return
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "missing log file"})
			return
		}
		defer file.Close()
		result, err := AnalyzeLog(file)
		if err != nil {
			writeJSON(w, 422, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, result)
	})
	mux.HandleFunc("POST /api/v1/agent/analyze", func(w http.ResponseWriter, r *http.Request) {
		var input agentRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&input); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		result, err := runAgent(input)
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, result)
	})
	address := os.Getenv("LOGSLEUTH_GO_ADDR")
	if address == "" {
		address = "127.0.0.1:8787"
	}
	log.Printf("LogSleuth Go engine listening on http://%s", address)
	log.Fatal(http.ListenAndServe(address, cors(mux)))
}
