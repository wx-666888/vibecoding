package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"regexp"

	"banner-fingerprint/internal/fingerprint"
)

var hexEscapeRegex = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)

type Handler struct {
	engine *fingerprint.Engine
	mux    *http.ServeMux
}

func NewHandler(engine *fingerprint.Engine) http.Handler {
	h := &Handler{
		engine: engine,
		mux:    http.NewServeMux(),
	}
	h.registerRoutes()
	return h
}

func (h *Handler) registerRoutes() {
	h.mux.HandleFunc("/health", h.handleHealth)
	h.mux.HandleFunc("/fingerprint", h.handleFingerprint)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// sanitizeJSONBytes fixes non-standard \xNN escapes into valid standard \u00NN escapes
func sanitizeJSONBytes(data []byte) []byte {
	if !bytes.Contains(data, []byte(`\x`)) {
		return data
	}
	return hexEscapeRegex.ReplaceAll(data, []byte(`\u00$1`))
}

func (h *Handler) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Limit body to 4 MiB
	maxBody := int64(4 << 20)
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		if err.Error() == "http: request body too large" {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "payload too large")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	cleanedBytes := sanitizeJSONBytes(bodyBytes)

	var inputs []fingerprint.Input
	dec := json.NewDecoder(bytes.NewReader(cleanedBytes))
	if err := dec.Decode(&inputs); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json array")
		return
	}

	// Ensure there is no trailing extraneous JSON token
	if dec.More() {
		writeJSONError(w, http.StatusBadRequest, "unexpected trailing json content")
		return
	}

	if len(inputs) > 5000 {
		writeJSONError(w, http.StatusBadRequest, "batch size exceeds maximum limit of 5000 items")
		return
	}

	results := h.engine.IdentifyBatch(inputs)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(results)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
