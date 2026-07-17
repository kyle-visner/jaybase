package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jaybase "github.com/kyle-visner/jaybase"
)

type testAPI struct {
	handler http.Handler
	store   *jaybase.Store
	backup  string
	tokens  map[string]string
}

func newTestAPI(t *testing.T) testAPI {
	t.Helper()
	tokens := map[string]string{
		"reader-agent": strings.Repeat("r", 64),
		"writer-agent": strings.Repeat("w", 64),
		"admin-agent":  strings.Repeat("a", 64),
	}
	records := make([]map[string]string, 0, len(tokens))
	for _, item := range []struct{ id, role string }{
		{"reader-agent", "reader"}, {"writer-agent", "writer"}, {"admin-agent", "admin"},
	} {
		sum := sha256.Sum256([]byte(tokens[item.id]))
		records = append(records, map[string]string{
			"id": item.id, "role": item.role, "sha256": hex.EncodeToString(sum[:]),
		})
	}
	authBytes, err := json.Marshal(map[string]any{"tokens": records})
	if err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(authPath, authBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := LoadAuthenticator(authPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := jaybase.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	backup := t.TempDir()
	api, err := New(Options{
		Store: store, Auth: auth, BackupDir: backup,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return testAPI{handler: api.Handler(), store: store, backup: backup, tokens: tokens}
}

func (api testAPI) request(t *testing.T, method, path, token, idempotency, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if idempotency != "" {
		req.Header.Set("Idempotency-Key", idempotency)
	}
	response := httptest.NewRecorder()
	api.handler.ServeHTTP(response, req)
	return response
}

func TestAPIAuthenticationAuthorizationAndIdempotentAppend(t *testing.T) {
	api := newTestAPI(t)
	if got := api.request(t, http.MethodGet, "/v1/root", "", "", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated root status = %d", got)
	}
	body := `{"type":"business.fact","entity_id":"customer:42","command":"fact assert","payload":{"value":"secret fact"},"expected_root":""}`
	if got := api.request(t, http.MethodPost, "/v1/events", api.tokens["reader-agent"], "request-0001", body).Code; got != http.StatusForbidden {
		t.Fatalf("reader append status = %d", got)
	}

	created := api.request(t, http.MethodPost, "/v1/events", api.tokens["writer-agent"], "request-0001", body)
	if created.Code != http.StatusCreated {
		t.Fatalf("append status = %d body=%s", created.Code, created.Body.String())
	}
	var createdBody struct {
		Hash     string `json:"hash"`
		Root     string `json:"root"`
		Replayed bool   `json:"replayed"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdBody); err != nil {
		t.Fatal(err)
	}
	if createdBody.Hash == "" || createdBody.Root != createdBody.Hash || createdBody.Replayed {
		t.Fatalf("unexpected append response: %#v", createdBody)
	}

	retry := api.request(t, http.MethodPost, "/v1/events", api.tokens["writer-agent"], "request-0001", body)
	if retry.Code != http.StatusOK || !strings.Contains(retry.Body.String(), `"replayed":true`) {
		t.Fatalf("retry status = %d body=%s", retry.Code, retry.Body.String())
	}
	changedBody := strings.Replace(body, "secret fact", "different fact", 1)
	conflict := api.request(t, http.MethodPost, "/v1/events", api.tokens["writer-agent"], "request-0001", changedBody)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("reused request key status = %d body=%s", conflict.Code, conflict.Body.String())
	}
	stale := api.request(t, http.MethodPost, "/v1/events", api.tokens["writer-agent"], "request-0002", changedBody)
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale-root status = %d body=%s", stale.Code, stale.Body.String())
	}

	metadata := api.request(t, http.MethodGet, "/v1/events", api.tokens["reader-agent"], "", "")
	if metadata.Code != http.StatusOK || strings.Contains(metadata.Body.String(), "secret fact") {
		t.Fatalf("metadata response exposed payload: status=%d body=%s", metadata.Code, metadata.Body.String())
	}
	withPayload := api.request(t, http.MethodGet, "/v1/events?include_payload=true", api.tokens["reader-agent"], "", "")
	if withPayload.Code != http.StatusOK || !strings.Contains(withPayload.Body.String(), "secret fact") ||
		!strings.Contains(withPayload.Body.String(), `"actor":"writer-agent"`) {
		t.Fatalf("payload response mismatch: status=%d body=%s", withPayload.Code, withPayload.Body.String())
	}
}

func TestAdminSnapshotEndpointCreatesKeylessArchive(t *testing.T) {
	api := newTestAPI(t)
	body := `{"type":"fact","command":"remember","payload":{"value":"classified"},"expected_root":""}`
	if response := api.request(t, http.MethodPost, "/v1/events", api.tokens["writer-agent"], "snapshot-request", body); response.Code != http.StatusCreated {
		t.Fatalf("append status=%d body=%s", response.Code, response.Body.String())
	}
	if response := api.request(t, http.MethodPost, "/v1/admin/snapshots", api.tokens["writer-agent"], "", ""); response.Code != http.StatusForbidden {
		t.Fatalf("writer snapshot status=%d", response.Code)
	}
	response := api.request(t, http.MethodPost, "/v1/admin/snapshots", api.tokens["admin-agent"], "", "")
	if response.Code != http.StatusCreated {
		t.Fatalf("admin snapshot status=%d body=%s", response.Code, response.Body.String())
	}
	var result jaybase.SnapshotInfo
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	archive, err := os.Open(filepath.Join(api.backup, result.Path))
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	gz, err := gzip.NewReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	tarReader := tar.NewReader(gz)
	var contents bytes.Buffer
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		contents.WriteString(header.Name)
		if _, err := io.Copy(&contents, tarReader); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(contents.String(), "classified") || strings.Contains(contents.String(), "keys/data.key") {
		t.Fatal("snapshot exposed plaintext or bundled a key")
	}
}
