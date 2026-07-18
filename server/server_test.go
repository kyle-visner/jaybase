package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jaybase "github.com/kyle-visner/jaybase"
)

type testAPI struct {
	handler http.Handler
	api     *API
	store   *jaybase.Store
	backup  string
	tokens  map[string]string
	logs    *bytes.Buffer
}

func newTestAPI(t *testing.T) testAPI {
	return newTestAPIWithOptions(t, nil)
}

func newTestAPIWithOptions(t *testing.T, configure func(*Options)) testAPI {
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
	t.Cleanup(func() { _ = store.Close() })
	backup := t.TempDir()
	logs := &bytes.Buffer{}
	options := Options{
		Store: store, Auth: auth, BackupDir: backup,
		Logger: slog.New(slog.NewJSONHandler(logs, nil)),
	}
	if configure != nil {
		configure(&options)
	}
	api, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return testAPI{handler: api.Handler(), api: api, store: store, backup: backup, tokens: tokens, logs: logs}
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

func TestBDDEventEndpointHonorsThePageLimitBeforeReadingHistory(t *testing.T) {
	api := newTestAPI(t)
	var roots []string
	for i := 0; i < 3; i++ {
		root, err := api.store.Append(jaybase.Context{Actor: "fixture"}, jaybase.AppendOptions{
			Type: "fact", Command: "remember", Payload: map[string]int{"sequence": i},
		})
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, root)
	}
	path := api.store.NodePath(roots[2])
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), "ciphertext", "ciphertexu", 1)), 0o600); err != nil {
		t.Fatal(err)
	}

	response := api.request(t, http.MethodGet, "/v1/events?limit=1", api.tokens["reader-agent"], "", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), roots[0]) {
		t.Fatalf("bounded page touched unrelated history: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestBDDOversizedJSONReturnsOneStructured413(t *testing.T) {
	api := newTestAPIWithOptions(t, func(options *Options) { options.MaxBodyBytes = 64 })
	body := `{"type":"fact","command":"remember","payload":{"value":"` + strings.Repeat("x", 128) + `"},"expected_root":""}`
	response := api.request(t, http.MethodPost, "/v1/events", api.tokens["writer-agent"], "oversized-request", body)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized response status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Count(response.Body.String(), `"error"`) != 1 || !strings.Contains(response.Body.String(), `"validation_error"`) {
		t.Fatalf("oversized response is not one structured error: %s", response.Body.String())
	}
}

func TestBDDIntegrityFailureUsesServerErrorAndNotReadyStatus(t *testing.T) {
	api := newTestAPI(t)
	root, err := api.store.Append(jaybase.Context{Actor: "fixture"}, jaybase.AppendOptions{
		Type: "fact", Command: "remember", Payload: map[string]bool{"valid": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := api.store.NodePath(root)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), "ciphertext", "ciphertexu", 1)), 0o600); err != nil {
		t.Fatal(err)
	}

	ready := api.request(t, http.MethodGet, "/health/ready", "", "", "")
	if ready.Code != http.StatusServiceUnavailable || !strings.Contains(ready.Body.String(), `"status":"not_ready"`) {
		t.Fatalf("readiness status=%d body=%s", ready.Code, ready.Body.String())
	}
	events := api.request(t, http.MethodGet, "/v1/events?include_payload=true", api.tokens["reader-agent"], "", "")
	if events.Code != http.StatusInternalServerError || !strings.Contains(events.Body.String(), `"integrity_error"`) {
		t.Fatalf("integrity read status=%d body=%s", events.Code, events.Body.String())
	}
}

func TestBDDAccessLogsAttributeAuthenticatedAndRejectedRequests(t *testing.T) {
	api := newTestAPI(t)
	validToken := api.tokens["reader-agent"]
	if response := api.request(t, http.MethodGet, "/v1/root", validToken, "", ""); response.Code != http.StatusOK {
		t.Fatalf("authenticated request status=%d", response.Code)
	}
	if response := api.request(t, http.MethodGet, "/v1/root", "invalid-token-that-is-long-enough-000000", "", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("rejected request status=%d", response.Code)
	}
	logs := api.logs.String()
	if !strings.Contains(logs, `"principal_id":"reader-agent"`) || !strings.Contains(logs, `"role":"reader"`) {
		t.Fatalf("authenticated principal missing from logs: %s", logs)
	}
	if !strings.Contains(logs, `"principal_id":"unauthenticated"`) {
		t.Fatalf("rejected principal marker missing from logs: %s", logs)
	}
	if strings.Contains(logs, validToken) {
		t.Fatal("access log leaked a bearer token")
	}
}

func TestBDDNamedRefUpdatesUseCompareAndSwap(t *testing.T) {
	api := newTestAPI(t)
	first, err := api.store.Append(jaybase.Context{Actor: "fixture"}, jaybase.AppendOptions{
		Type: "fact", Command: "remember", Payload: map[string]int{"sequence": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := api.store.Append(jaybase.Context{Actor: "fixture"}, jaybase.AppendOptions{
		Type: "fact", Command: "remember", Payload: map[string]int{"sequence": 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	createBody := fmt.Sprintf(`{"root":%q,"expected_root":""}`, first)
	created := api.request(t, http.MethodPut, "/v1/refs/checkpoint", api.tokens["writer-agent"], "", createBody)
	if created.Code != http.StatusOK {
		t.Fatalf("create named ref status=%d body=%s", created.Code, created.Body.String())
	}
	staleBody := fmt.Sprintf(`{"root":%q,"expected_root":""}`, second)
	stale := api.request(t, http.MethodPut, "/v1/refs/checkpoint", api.tokens["writer-agent"], "", staleBody)
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale named ref status=%d body=%s", stale.Code, stale.Body.String())
	}
	updateBody := fmt.Sprintf(`{"root":%q,"expected_root":%q}`, second, first)
	updated := api.request(t, http.MethodPut, "/v1/refs/checkpoint", api.tokens["writer-agent"], "", updateBody)
	if updated.Code != http.StatusOK {
		t.Fatalf("CAS named ref status=%d body=%s", updated.Code, updated.Body.String())
	}
}

func TestBDDSnapshotRetentionCapacityAndClockAreEnforced(t *testing.T) {
	api := newTestAPIWithOptions(t, func(options *Options) {
		options.SnapshotRetention = 2
		options.SnapshotMinFreeBytes = 1
	})
	root, err := api.store.Append(jaybase.Context{Actor: "fixture"}, jaybase.AppendOptions{
		Type: "fact", Command: "remember", Payload: map[string]bool{"valid": true},
	})
	if err != nil || root == "" {
		t.Fatalf("append root=%q err=%v", root, err)
	}
	base := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	call := 0
	api.store.SetClock(func() time.Time {
		value := base.Add(time.Duration(call) * time.Second)
		call++
		return value
	})
	for i := 0; i < 3; i++ {
		response := api.request(t, http.MethodPost, "/v1/admin/snapshots", api.tokens["admin-agent"], "", "")
		if response.Code != http.StatusCreated {
			t.Fatalf("snapshot %d status=%d body=%s", i, response.Code, response.Body.String())
		}
		if i == 0 && !strings.Contains(response.Body.String(), "jaybase-20300102T030405.000000000Z.tar.gz") {
			t.Fatalf("snapshot filename did not use store clock: %s", response.Body.String())
		}
	}
	archives, err := filepath.Glob(filepath.Join(api.backup, "jaybase-*.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if len(archives) != 2 {
		t.Fatalf("retention kept %d snapshots, want 2: %v", len(archives), archives)
	}

	api.api.availableBytes = func(string) (uint64, error) { return 0, nil }
	capacity := api.request(t, http.MethodPost, "/v1/admin/snapshots", api.tokens["admin-agent"], "", "")
	if capacity.Code != http.StatusInsufficientStorage || !strings.Contains(capacity.Body.String(), `"capacity_exceeded"`) {
		t.Fatalf("capacity status=%d body=%s", capacity.Code, capacity.Body.String())
	}
}
