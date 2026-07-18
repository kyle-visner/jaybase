package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	jaybase "github.com/kyle-visner/jaybase"
)

const defaultMaxBodyBytes int64 = 1 << 20
const defaultSnapshotRetention = 24

type Options struct {
	Store             *jaybase.Store
	Auth              *Authenticator
	BackupDir         string
	Logger            *slog.Logger
	MaxBodyBytes      int64
	SnapshotRetention int
	// SnapshotMinFreeBytes is the reserve preserved after the estimated archive;
	// zero explicitly disables the reserve.
	SnapshotMinFreeBytes uint64
}

type API struct {
	store                *jaybase.Store
	auth                 *Authenticator
	backupDir            string
	logger               *slog.Logger
	maxBody              int64
	snapshotRetention    int
	snapshotMinFreeBytes uint64
	availableBytes       func(string) (uint64, error)
	pruneSnapshots       func(string, int) error
	snapshotMu           sync.Mutex
	mux                  *http.ServeMux
}

type principalContextKey struct{}

func New(options Options) (*API, error) {
	if options.Store == nil {
		return nil, fmt.Errorf("store is required")
	}
	if options.Auth == nil {
		return nil, fmt.Errorf("authenticator is required")
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	if options.MaxBodyBytes <= 0 {
		options.MaxBodyBytes = defaultMaxBodyBytes
	}
	if options.SnapshotRetention <= 0 {
		options.SnapshotRetention = defaultSnapshotRetention
	}
	api := &API{
		store: options.Store, auth: options.Auth, backupDir: options.BackupDir,
		logger: options.Logger, maxBody: options.MaxBodyBytes,
		snapshotRetention: options.SnapshotRetention, snapshotMinFreeBytes: options.SnapshotMinFreeBytes,
		availableBytes: diskAvailableBytes, pruneSnapshots: pruneSnapshots, mux: http.NewServeMux(),
	}
	api.routes()
	return api, nil
}

func (a *API) Handler() http.Handler {
	return a.securityHeaders(a.accessLog(a.mux))
}

func (a *API) routes() {
	a.mux.HandleFunc("GET /health/live", a.live)
	a.mux.HandleFunc("GET /health/ready", a.ready)
	a.mux.Handle("GET /v1/root", a.require(RoleReader, http.HandlerFunc(a.root)))
	a.mux.Handle("GET /v1/events", a.require(RoleReader, http.HandlerFunc(a.events)))
	a.mux.Handle("POST /v1/events", a.require(RoleWriter, http.HandlerFunc(a.appendEvent)))
	a.mux.Handle("GET /v1/refs/{name}", a.require(RoleReader, http.HandlerFunc(a.getNamedRef)))
	a.mux.Handle("PUT /v1/refs/{name}", a.require(RoleWriter, http.HandlerFunc(a.putNamedRef)))
	a.mux.Handle("POST /v1/admin/snapshots", a.require(RoleAdmin, http.HandlerFunc(a.snapshot)))
	a.mux.Handle("POST /v1/admin/verify", a.require(RoleAdmin, http.HandlerFunc(a.verify)))
}

func (a *API) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "live"})
}

func (a *API) ready(w http.ResponseWriter, _ *http.Request) {
	if err := a.store.VerifyHead(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready",
			"error":  jaybase.AppError{Code: jaybase.ErrIntegrity, Message: "store head verification failed"},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (a *API) root(w http.ResponseWriter, _ *http.Request) {
	root, err := a.store.CurrentRoot()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"root": root})
}

type appendRequest struct {
	Type         string          `json:"type"`
	EntityID     string          `json:"entity_id,omitempty"`
	Command      string          `json:"command"`
	Payload      json.RawMessage `json:"payload"`
	ExpectedRoot *string         `json:"expected_root"`
}

func (a *API) appendEvent(w http.ResponseWriter, r *http.Request) {
	if !hasJSONContentType(r) {
		writeError(w, http.StatusUnsupportedMediaType, jaybase.ErrValidation, "Content-Type must be application/json")
		return
	}
	requestKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if len(requestKey) < 8 || len(requestKey) > 200 {
		writeError(w, http.StatusBadRequest, jaybase.ErrValidation, "Idempotency-Key must be between 8 and 200 characters")
		return
	}
	var request appendRequest
	if err := decodeJSON(w, r, a.maxBody, &request); err != nil {
		writeDecodeError(w, err)
		return
	}
	if request.ExpectedRoot == nil {
		writeError(w, http.StatusBadRequest, jaybase.ErrValidation, "expected_root is required; use an empty string for the first event")
		return
	}
	if len(request.Payload) == 0 {
		writeError(w, http.StatusBadRequest, jaybase.ErrValidation, "payload is required")
		return
	}
	canonical, err := json.Marshal(request)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	principal := principalFromContext(r.Context())
	requestIDSum := sha256.Sum256([]byte(principal.ID + "\x00" + requestKey))
	requestHashSum := sha256.Sum256(canonical)
	hash, replayed, err := a.store.AppendIdempotent(
		jaybase.Context{Actor: principal.ID, Role: principal.Role.String()},
		jaybase.AppendOptions{
			Type: request.Type, EntityID: request.EntityID, Command: request.Command,
			Payload: request.Payload,
		},
		*request.ExpectedRoot,
		"sha256:"+hex.EncodeToString(requestIDSum[:]),
		"sha256:"+hex.EncodeToString(requestHashSum[:]),
	)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	currentRoot, err := a.store.CurrentRoot()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"hash": hash, "root": currentRoot, "replayed": replayed})
}

type eventResponse struct {
	Schema    int             `json:"schema"`
	Hash      string          `json:"hash"`
	Type      string          `json:"type"`
	EntityID  string          `json:"entity_id,omitempty"`
	Parents   []string        `json:"parents"`
	Actor     string          `json:"actor"`
	Role      string          `json:"role"`
	Command   string          `json:"command"`
	CreatedAt time.Time       `json:"created_at"`
	RequestID string          `json:"request_id,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

func (a *API) events(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1000 {
			writeError(w, http.StatusBadRequest, jaybase.ErrValidation, "limit must be between 1 and 1000")
			return
		}
		limit = parsed
	}
	page, err := a.store.EventPage(r.URL.Query().Get("after"), limit)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	includePayload := r.URL.Query().Get("include_payload") == "true"
	events := make([]eventResponse, 0, len(page.Nodes))
	for _, node := range page.Nodes {
		event := eventResponse{
			Schema: node.Schema, Hash: node.Hash, Type: node.Type, EntityID: node.EntityID,
			Parents: node.Parents, Actor: node.Actor, Role: node.Role, Command: node.Command,
			CreatedAt: node.CreatedAt, RequestID: node.RequestID,
		}
		if includePayload {
			payload, err := a.store.NodePayload(node)
			if err != nil {
				writeAPIError(w, err)
				return
			}
			event.Payload = payload
		}
		events = append(events, event)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events, "root": page.Root, "has_more": page.HasMore,
	})
}

func (a *API) getNamedRef(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	root, err := a.store.NamedRef(name)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": name, "root": root})
}

func (a *API) putNamedRef(w http.ResponseWriter, r *http.Request) {
	if !hasJSONContentType(r) {
		writeError(w, http.StatusUnsupportedMediaType, jaybase.ErrValidation, "Content-Type must be application/json")
		return
	}
	var request struct {
		Root         string  `json:"root"`
		ExpectedRoot *string `json:"expected_root"`
	}
	if err := decodeJSON(w, r, a.maxBody, &request); err != nil {
		writeDecodeError(w, err)
		return
	}
	if request.ExpectedRoot == nil {
		writeError(w, http.StatusBadRequest, jaybase.ErrValidation, "expected_root is required; use an empty string to create the ref")
		return
	}
	if err := a.store.WriteNamedRefAt(r.PathValue("name"), request.Root, *request.ExpectedRoot); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": r.PathValue("name"), "root": request.Root})
}

func (a *API) snapshot(w http.ResponseWriter, _ *http.Request) {
	a.snapshotMu.Lock()
	defer a.snapshotMu.Unlock()
	if a.backupDir == "" {
		writeError(w, http.StatusServiceUnavailable, jaybase.ErrValidation, "snapshot directory is not configured")
		return
	}
	if err := os.MkdirAll(a.backupDir, 0o700); err != nil {
		writeAPIError(w, err)
		return
	}
	estimate, err := a.store.SnapshotSizeEstimate()
	if err != nil {
		writeAPIError(w, err)
		return
	}
	available, err := a.availableBytes(a.backupDir)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if available < a.snapshotMinFreeBytes || available-a.snapshotMinFreeBytes < estimate {
		writeError(w, http.StatusInsufficientStorage, jaybase.ErrCapacity, "insufficient free space for a safe snapshot")
		return
	}
	info, err := a.store.CreateSnapshot(a.backupDir)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if err := a.pruneSnapshots(a.backupDir, a.snapshotRetention); err != nil {
		a.logger.Error("snapshot retention cleanup failed", "error", err,
			"snapshot", info.Path, "root", info.Root)
	}
	writeJSON(w, http.StatusCreated, info)
}

func pruneSnapshots(dir string, retain int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.Type().IsRegular() && strings.HasPrefix(name, "jaybase-") && strings.HasSuffix(name, ".tar.gz") {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for len(names) > retain {
		if err := os.Remove(filepath.Join(dir, names[0])); err != nil {
			return err
		}
		names = names[1:]
	}
	return nil
}

func (a *API) verify(w http.ResponseWriter, _ *http.Request) {
	nodes, err := a.store.AuditLog()
	if err == nil {
		for _, node := range nodes {
			if _, payloadErr := a.store.NodePayload(node); payloadErr != nil {
				err = payloadErr
				break
			}
		}
	}
	if err != nil {
		writeAPIError(w, err)
		return
	}
	root := ""
	if len(nodes) > 0 {
		root = nodes[len(nodes)-1].Hash
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "verified", "root": root, "nodes": len(nodes)})
}

func (a *API) require(minimum Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			setRequestPrincipal(w, "unauthenticated", "")
			w.Header().Set("WWW-Authenticate", `Bearer realm="jaybase"`)
			writeError(w, http.StatusUnauthorized, jaybase.ErrPermission, "valid bearer token required")
			return
		}
		principal, ok := a.auth.Authenticate(strings.TrimSpace(parts[1]))
		if !ok {
			setRequestPrincipal(w, "unauthenticated", "")
			w.Header().Set("WWW-Authenticate", `Bearer realm="jaybase"`)
			writeError(w, http.StatusUnauthorized, jaybase.ErrPermission, "valid bearer token required")
			return
		}
		setRequestPrincipal(w, principal.ID, principal.Role.String())
		if principal.Role < minimum {
			writeError(w, http.StatusForbidden, jaybase.ErrPermission, "credential does not have permission for this operation")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), principalContextKey{}, principal))
		next.ServeHTTP(w, r)
	})
}

func principalFromContext(ctx context.Context) Principal {
	principal, _ := ctx.Value(principalContextKey{}).(Principal)
	return principal
}

func decodeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("request body must contain exactly one JSON object")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		writeError(w, http.StatusRequestEntityTooLarge, jaybase.ErrValidation, "request body exceeds the configured size limit")
		return
	}
	writeError(w, http.StatusBadRequest, jaybase.ErrValidation, err.Error())
}

func hasJSONContentType(r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

func writeAPIError(w http.ResponseWriter, err error) {
	var appErr *jaybase.AppError
	if errors.As(err, &appErr) {
		status := http.StatusInternalServerError
		switch appErr.Code {
		case jaybase.ErrValidation:
			status = http.StatusBadRequest
		case jaybase.ErrPermission:
			status = http.StatusForbidden
		case jaybase.ErrNotFound:
			status = http.StatusNotFound
		case jaybase.ErrConflict:
			status = http.StatusConflict
		case jaybase.ErrIntegrity:
			status = http.StatusInternalServerError
		case jaybase.ErrCapacity:
			status = http.StatusInsufficientStorage
		}
		writeError(w, status, appErr.Code, appErr.Message)
		return
	}
	writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
}

func writeError(w http.ResponseWriter, status int, code jaybase.ErrorCode, message string) {
	writeJSON(w, status, map[string]any{"error": jaybase.AppError{Code: code, Message: message}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type responseRecorder struct {
	http.ResponseWriter
	status      int
	principalID string
	role        string
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func setRequestPrincipal(w http.ResponseWriter, id, role string) {
	if recorder, ok := w.(*responseRecorder); ok {
		recorder.principalID = id
		recorder.role = role
	}
}

func (a *API) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &responseRecorder{ResponseWriter: w, status: http.StatusOK, principalID: "anonymous"}
		next.ServeHTTP(recorder, r)
		a.logger.Info("request", "method", r.Method, "path", r.URL.Path,
			"status", recorder.status, "duration_ms", time.Since(started).Milliseconds(),
			"principal_id", recorder.principalID, "role", recorder.role)
	})
}

func (a *API) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
