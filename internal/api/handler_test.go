package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"banner-fingerprint/internal/fingerprint"
)

func setupTestHandler(t *testing.T) http.Handler {
	engine, err := fingerprint.LoadRules("")
	if err != nil {
		t.Fatalf("failed to load engine: %v", err)
	}
	return NewHandler(engine)
}

func TestHealthEndpoint(t *testing.T) {
	handler := setupTestHandler(t)

	// GET /health
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %s", resp["status"])
	}

	// POST /health should fail 405
	req2 := httptest.NewRequest(http.MethodPost, "/health", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w2.Code)
	}
}

func TestFingerprintEndpoint(t *testing.T) {
	handler := setupTestHandler(t)

	// Test with valid JSON
	body := `[
		{"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		{"ip": "1.2.3.5", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}
	]`

	req := httptest.NewRequest(http.MethodPost, "/fingerprint", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var results []fingerprint.Result
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatalf("failed to unmarshal results: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	if results[0].Protocol != "SSH" || results[0].Product != "OpenSSH" || results[0].Version != "8.9p1" || results[0].OSHint != "Ubuntu" {
		t.Errorf("unexpected result[0]: %+v", results[0])
	}
	if results[1].Protocol != "HTTP" || results[1].Product != "nginx" || results[1].Version != "1.24.0" {
		t.Errorf("unexpected result[1]: %+v", results[1])
	}
}

func TestFingerprintNonStandardHexEscapes(t *testing.T) {
	handler := setupTestHandler(t)

	// Test non-standard \x00 in raw JSON
	body := `[{"ip": "1.2.3.7", "port": 3306, "banner": "J\x00\x00\x00\n8.0.32\x00"}]`

	req := httptest.NewRequest(http.MethodPost, "/fingerprint", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var results []fingerprint.Result
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatalf("failed to unmarshal results: %v", err)
	}

	if len(results) != 1 || results[0].Protocol != "MySQL" || results[0].Version != "8.0.32" {
		t.Errorf("unexpected result: %+v", results)
	}
}

func TestFingerprintInvalidPayload(t *testing.T) {
	handler := setupTestHandler(t)

	// Malformed JSON
	body := `{"ip": "1.2.3.4"`
	req := httptest.NewRequest(http.MethodPost, "/fingerprint", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", w.Code)
	}
}
