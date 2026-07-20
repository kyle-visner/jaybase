package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func TestBDDIncrementalEventReplayKeepsTheFirstRootAsItsBoundary(t *testing.T) {
	api := newTestAPI(t)
	var roots []string
	appendEvent := func(sequence int) {
		t.Helper()
		root, err := api.store.Append(jaybase.Context{Actor: "fixture"}, jaybase.AppendOptions{
			Type: "fact", Command: "remember", Payload: map[string]int{"sequence": sequence},
		})
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, root)
	}
	for i := 0; i < 4; i++ {
		appendEvent(i)
	}

	type replayResponse struct {
		Events []struct {
			Hash    string          `json:"hash"`
			Payload json.RawMessage `json:"payload"`
		} `json:"events"`
		Root    string `json:"root"`
		HasMore bool   `json:"has_more"`
	}
	decodePage := func(response *httptest.ResponseRecorder) replayResponse {
		t.Helper()
		if response.Code != http.StatusOK {
			t.Fatalf("event page status=%d body=%s", response.Code, response.Body.String())
		}
		var page replayResponse
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		return page
	}

	first := decodePage(api.request(t, http.MethodGet, "/v1/events?limit=3", api.tokens["reader-agent"], "", ""))
	target := first.Root
	if target != roots[3] || len(first.Events) != 3 || !first.HasMore {
		t.Fatalf("unexpected first page: %#v", first)
	}
	for _, event := range first.Events {
		if len(event.Payload) != 0 {
			t.Fatalf("metadata-only page exposed a payload: %#v", event)
		}
	}

	// Model another writer advancing the live root between HTTP page requests.
	appendEvent(4)
	appendEvent(5)
	path := "/v1/events?after=" + first.Events[len(first.Events)-1].Hash + "&limit=3&include_payload=true"
	second := decodePage(api.request(t, http.MethodGet, path, api.tokens["reader-agent"], "", ""))
	if second.Root != roots[5] || len(second.Events) != 3 || second.HasMore {
		t.Fatalf("unexpected second page after concurrent appends: %#v", second)
	}

	applied := make([]string, 0, 4)
	for _, event := range first.Events {
		applied = append(applied, event.Hash)
	}
	reachedTarget := false
	for _, event := range second.Events {
		if len(event.Payload) == 0 {
			t.Fatalf("include_payload page omitted a payload: %#v", event)
		}
		applied = append(applied, event.Hash)
		if event.Hash == target {
			reachedTarget = true
			break
		}
	}
	if !reachedTarget || len(applied) != 4 {
		t.Fatalf("replay did not stop at captured target %s: %#v", target, applied)
	}

	caughtUpPath := "/v1/events?after=" + roots[5] + "&limit=3"
	caughtUp := decodePage(api.request(t, http.MethodGet, caughtUpPath, api.tokens["reader-agent"], "", ""))
	if len(caughtUp.Events) != 0 || caughtUp.Root != roots[5] || caughtUp.HasMore {
		t.Fatalf("current-root checkpoint did not terminate with an empty page: %#v", caughtUp)
	}

	missing := api.request(t, http.MethodGet, "/v1/events?after=sha256:missing", api.tokens["reader-agent"], "", "")
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unknown checkpoint status=%d body=%s", missing.Code, missing.Body.String())
	}
	var failure struct {
		Error jaybase.AppError `json:"error"`
	}
	if err := json.Unmarshal(missing.Body.Bytes(), &failure); err != nil {
		t.Fatal(err)
	}
	if failure.Error.Code != jaybase.ErrNotFound {
		t.Fatalf("unknown checkpoint error=%#v", failure.Error)
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
	if _, err := api.store.Append(jaybase.Context{Actor: "fixture"}, jaybase.AppendOptions{
		Type: "fact", Command: "remember", Payload: map[string]bool{"sensitive": true},
	}); err != nil {
		t.Fatal(err)
	}
	validToken := api.tokens["reader-agent"]
	if response := api.request(t, http.MethodGet, "/v1/root", validToken, "", ""); response.Code != http.StatusOK {
		t.Fatalf("authenticated request status=%d", response.Code)
	}
	if response := api.request(t, http.MethodGet, "/v1/root", "invalid-token-that-is-long-enough-000000", "", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("rejected request status=%d", response.Code)
	}
	if response := api.request(t, http.MethodGet, "/v1/events?include_payload=true&limit=25", validToken, "", ""); response.Code != http.StatusOK {
		t.Fatalf("payload read status=%d", response.Code)
	}
	if response := api.request(t, http.MethodGet, "/v1/events?include_payload=true&limit=25&after=checkpoint", validToken, "", ""); response.Code != http.StatusNotFound {
		t.Fatalf("audited read status=%d", response.Code)
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
	for _, field := range []string{`"include_payload":true`, `"payloads_decrypted":1`, `"payloads_decrypted":0`, `"limit":25`, `"after_present":true`} {
		if !strings.Contains(logs, field) {
			t.Fatalf("safe read field %s missing from logs: %s", field, logs)
		}
	}
}

func TestMinimumRootReadinessAndAdminCheckDetectRollback(t *testing.T) {
	api := newTestAPI(t)
	root, err := api.store.Append(jaybase.Context{Actor: "fixture"}, jaybase.AppendOptions{
		Type: "fact", Command: "remember", Payload: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	api.api.minimumRoot = root
	if response := api.request(t, http.MethodGet, "/health/ready", "", "", ""); response.Code != http.StatusOK {
		t.Fatalf("pinned readiness status=%d body=%s", response.Code, response.Body.String())
	}
	path := "/v1/admin/check-root?root=" + root
	if response := api.request(t, http.MethodGet, path, api.tokens["admin-agent"], "", ""); response.Code != http.StatusOK {
		t.Fatalf("check-root status=%d body=%s", response.Code, response.Body.String())
	}
	missing := "sha256:" + strings.Repeat("0", 64)
	api.api.minimumRoot = missing
	if response := api.request(t, http.MethodGet, "/health/ready", "", "", ""); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing pin readiness status=%d body=%s", response.Code, response.Body.String())
	}
	if response := api.request(t, http.MethodGet, "/v1/admin/check-root?root="+missing, api.tokens["admin-agent"], "", ""); response.Code != http.StatusConflict {
		t.Fatalf("missing check-root status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPerPrincipalAndFailedAuthRateLimits(t *testing.T) {
	api := newTestAPIWithOptions(t, func(options *Options) {
		options.RateLimitPerMinute = 1
		options.FailedAuthLimitPerMinute = 1
	})
	if response := api.request(t, http.MethodGet, "/v1/root", api.tokens["reader-agent"], "", ""); response.Code != http.StatusOK {
		t.Fatalf("first authenticated status=%d", response.Code)
	}
	if response := api.request(t, http.MethodGet, "/v1/root", api.tokens["reader-agent"], "", ""); response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("authenticated limit status=%d headers=%v", response.Code, response.Header())
	}
	bad := "invalid-token-that-is-long-enough-000000"
	if response := api.request(t, http.MethodGet, "/v1/root", bad, "", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("first invalid status=%d", response.Code)
	}
	if response := api.request(t, http.MethodGet, "/v1/root", bad, "", ""); response.Code != http.StatusTooManyRequests {
		t.Fatalf("failed auth limit status=%d", response.Code)
	}
}

func TestDecodeErrorsDoNotExposeParserDetails(t *testing.T) {
	api := newTestAPI(t)
	response := api.request(t, http.MethodPost, "/v1/events", api.tokens["writer-agent"], "request-parse", `{"unknown_secret_field":`)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "exactly one valid JSON object") {
		t.Fatalf("decode status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "unknown_secret_field") || strings.Contains(response.Body.String(), "unexpected EOF") {
		t.Fatalf("decode error exposed parser detail: %s", response.Body.String())
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

func TestBDDExplicitZeroSnapshotReserveIsHonored(t *testing.T) {
	api := newTestAPIWithOptions(t, func(options *Options) {
		options.SnapshotMinFreeBytes = 0
	})
	if _, err := api.store.Append(jaybase.Context{Actor: "fixture"}, jaybase.AppendOptions{
		Type: "fact", Command: "remember", Payload: map[string]bool{"valid": true},
	}); err != nil {
		t.Fatal(err)
	}
	api.api.availableBytes = func(string) (uint64, error) { return 2 << 20, nil }

	response := api.request(t, http.MethodPost, "/v1/admin/snapshots", api.tokens["admin-agent"], "", "")
	if response.Code != http.StatusCreated {
		t.Fatalf("explicit zero reserve status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestBDDPruneFailureDoesNotHideDurableSnapshot(t *testing.T) {
	api := newTestAPIWithOptions(t, func(options *Options) {
		options.SnapshotMinFreeBytes = 0
	})
	if _, err := api.store.Append(jaybase.Context{Actor: "fixture"}, jaybase.AppendOptions{
		Type: "fact", Command: "remember", Payload: map[string]bool{"valid": true},
	}); err != nil {
		t.Fatal(err)
	}
	api.api.pruneSnapshots = func(string, int) error { return errors.New("retention storage unavailable") }

	response := api.request(t, http.MethodPost, "/v1/admin/snapshots", api.tokens["admin-agent"], "", "")
	if response.Code != http.StatusCreated {
		t.Fatalf("durable snapshot hidden by prune failure: status=%d body=%s", response.Code, response.Body.String())
	}
	var info jaybase.SnapshotInfo
	if err := json.Unmarshal(response.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(api.backup, info.Path)); err != nil {
		t.Fatalf("created snapshot missing after prune failure: %v", err)
	}
	if !strings.Contains(api.logs.String(), "snapshot retention cleanup failed") ||
		!strings.Contains(api.logs.String(), "retention storage unavailable") {
		t.Fatalf("prune failure was not logged: %s", api.logs.String())
	}
}
