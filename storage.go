package jaybase

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const schemaVersion = 1

type ErrorCode string

const (
	ErrValidation ErrorCode = "validation_error"
	ErrPermission ErrorCode = "permission_denied"
	ErrNotFound   ErrorCode = "not_found"
	ErrConflict   ErrorCode = "conflict"
)

type AppError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

func (e *AppError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func appErr(code ErrorCode, format string, args ...any) *AppError {
	return &AppError{Code: code, Message: fmt.Sprintf(format, args...)}
}

type Store struct {
	dir string
	now func() time.Time
	key []byte
	mu  sync.RWMutex
}

type Context struct {
	Actor string
	Role  string
}

type AppendOptions struct {
	Type        string
	EntityID    string
	Command     string
	Payload     any
	CreatedAt   time.Time
	RequestID   string
	RequestHash string
}

type Node struct {
	Schema        int               `json:"schema"`
	Hash          string            `json:"hash"`
	Type          string            `json:"type"`
	EntityID      string            `json:"entity_id,omitempty"`
	Parents       []string          `json:"parents"`
	Payload       json.RawMessage   `json:"payload,omitempty"`
	SealedPayload *EncryptedPayload `json:"sealed_payload,omitempty"`
	Actor         string            `json:"actor"`
	Role          string            `json:"role"`
	Command       string            `json:"command"`
	CreatedAt     time.Time         `json:"created_at"`
	RequestID     string            `json:"request_id,omitempty"`
	RequestHash   string            `json:"request_hash,omitempty"`
}

type nodeContent struct {
	Schema        int               `json:"schema"`
	Type          string            `json:"type"`
	EntityID      string            `json:"entity_id,omitempty"`
	Parents       []string          `json:"parents"`
	Payload       json.RawMessage   `json:"payload,omitempty"`
	SealedPayload *EncryptedPayload `json:"sealed_payload,omitempty"`
	Actor         string            `json:"actor"`
	Role          string            `json:"role"`
	Command       string            `json:"command"`
	CreatedAt     time.Time         `json:"created_at"`
	RequestID     string            `json:"request_id,omitempty"`
	RequestHash   string            `json:"request_hash,omitempty"`
}

type EncryptedPayload struct {
	Algorithm  string `json:"algorithm"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func Open(dir string) (*Store, error) {
	return OpenStore(dir)
}

func OpenStore(dir string) (*Store, error) {
	return openStore(dir, "", false)
}

// OpenStoreWithDataKey opens a store with an explicit base64- or hex-encoded
// 32-byte key. Host processes should use this instead of the local key fallback.
func OpenStoreWithDataKey(dir, encodedKey string) (*Store, error) {
	return openStore(dir, encodedKey, true)
}

func openStore(dir, encodedKey string, requireExplicitKey bool) (*Store, error) {
	if dir == "" {
		dir = ".jaybase"
	}
	s := &Store{dir: dir, now: func() time.Time { return time.Now().UTC() }}
	for _, child := range []string{"objects/nodes", "refs/named", "keys"} {
		path := filepath.Join(dir, child)
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return nil, err
		}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	var key []byte
	var err error
	if requireExplicitKey {
		if strings.TrimSpace(encodedKey) == "" {
			return nil, appErr(ErrValidation, "an explicit data key is required")
		}
		key, err = decodeKey(strings.TrimSpace(encodedKey))
	} else {
		key, err = loadOrCreateKey(dir)
	}
	if err != nil {
		return nil, err
	}
	s.key = key
	return s, nil
}

func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now == nil {
		s.now = func() time.Time { return time.Now().UTC() }
		return
	}
	s.now = now
}

func (s *Store) Dir() string {
	return s.dir
}

func (s *Store) rootPath() string {
	return filepath.Join(s.dir, "refs", "root")
}

func (s *Store) CurrentRoot() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentRoot()
}

// VerifyHead verifies that the current root points to a complete, correctly
// addressed node. It is intentionally constant-time with respect to history
// length and is suitable for readiness probes.
func (s *Store) VerifyHead() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	root, err := s.currentRoot()
	if err != nil || root == "" {
		return err
	}
	_, err = s.readNode(root)
	return err
}

func (s *Store) currentRoot() (string, error) {
	b, err := os.ReadFile(s.rootPath())
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (s *Store) Append(ctx Context, opts AppendOptions) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.append(ctx, opts, nil)
}

// AppendAt appends only when expectedRoot is still the current root. Passing an
// empty expectedRoot is how a caller safely creates the first node in a store.
func (s *Store) AppendAt(ctx Context, opts AppendOptions, expectedRoot string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.append(ctx, opts, &expectedRoot)
}

// AppendIdempotent combines optimistic concurrency with a durable request ID.
// A retry of the same request returns its original node even if newer nodes have
// since been appended. Reusing a request ID for different content is rejected.
func (s *Store) AppendIdempotent(ctx Context, opts AppendOptions, expectedRoot, requestID, requestHash string) (string, bool, error) {
	requestID = strings.TrimSpace(requestID)
	requestHash = strings.TrimSpace(requestHash)
	if requestID == "" || requestHash == "" {
		return "", false, appErr(ErrValidation, "request ID and request hash are required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	root, err := s.currentRoot()
	if err != nil {
		return "", false, err
	}
	seen := make(map[string]bool)
	for cursor := root; cursor != ""; {
		if seen[cursor] {
			return "", false, appErr(ErrValidation, "cycle detected while looking up request ID at %s", cursor)
		}
		seen[cursor] = true
		node, err := s.readNode(cursor)
		if err != nil {
			return "", false, err
		}
		if node.RequestID == requestID {
			if node.RequestHash != requestHash {
				return "", false, appErr(ErrConflict, "request ID was already used for different content")
			}
			return node.Hash, true, nil
		}
		if len(node.Parents) == 0 {
			break
		}
		if len(node.Parents) != 1 {
			return "", false, appErr(ErrValidation, "merge roots are not supported")
		}
		cursor = node.Parents[0]
	}

	opts.RequestID = requestID
	opts.RequestHash = requestHash
	hash, err := s.append(ctx, opts, &expectedRoot)
	return hash, false, err
}

func (s *Store) append(ctx Context, opts AppendOptions, expectedRoot *string) (string, error) {
	opts.Type = strings.TrimSpace(opts.Type)
	opts.EntityID = strings.TrimSpace(opts.EntityID)
	opts.Command = strings.TrimSpace(opts.Command)
	if opts.Type == "" {
		return "", appErr(ErrValidation, "node type is required")
	}
	root, err := s.currentRoot()
	if err != nil {
		return "", err
	}
	if expectedRoot != nil && root != *expectedRoot {
		return "", appErr(ErrConflict, "root changed: expected %q, current %q", *expectedRoot, root)
	}
	parents := []string{}
	if root != "" {
		parents = []string{root}
	}
	raw, err := json.Marshal(opts.Payload)
	if err != nil {
		return "", err
	}
	sealed, err := encryptPayload(s.key, raw)
	if err != nil {
		return "", err
	}
	created := opts.CreatedAt
	if created.IsZero() {
		created = s.now()
	}
	created = created.UTC().Truncate(time.Microsecond)
	content := nodeContent{
		Schema: schemaVersion, Type: opts.Type, EntityID: opts.EntityID, Parents: parents,
		SealedPayload: sealed, Actor: ctx.Actor, Role: ctx.Role, Command: opts.Command, CreatedAt: created,
		RequestID: opts.RequestID, RequestHash: opts.RequestHash,
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(contentBytes)
	hash := "sha256:" + hex.EncodeToString(sum[:])
	node := Node{
		Schema: schemaVersion, Hash: hash, Type: opts.Type, EntityID: opts.EntityID, Parents: parents,
		SealedPayload: sealed, Actor: ctx.Actor, Role: ctx.Role, Command: opts.Command, CreatedAt: created,
		RequestID: opts.RequestID, RequestHash: opts.RequestHash,
	}
	path := s.NodePath(hash)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		nodeBytes, err := json.MarshalIndent(node, "", "  ")
		if err != nil {
			return "", err
		}
		if err := atomicCreateFile(path, append(nodeBytes, '\n'), 0o600); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	if err := atomicWriteFile(s.rootPath(), []byte(hash+"\n"), 0o600); err != nil {
		return "", err
	}
	return hash, nil
}

func (s *Store) NodePath(hash string) string {
	name := strings.TrimPrefix(hash, "sha256:")
	return filepath.Join(s.dir, "objects", "nodes", name+".json")
}

func (s *Store) readNode(hash string) (Node, error) {
	var node Node
	if err := validateHash(hash); err != nil {
		return node, err
	}
	b, err := os.ReadFile(s.NodePath(hash))
	if err != nil {
		return node, err
	}
	if err := json.Unmarshal(b, &node); err != nil {
		return node, err
	}
	if node.Hash != hash {
		return node, appErr(ErrValidation, "node address %s contains node %s", hash, node.Hash)
	}
	if err := verifyNode(node); err != nil {
		return node, err
	}
	return node, nil
}

func verifyNode(node Node) error {
	content := nodeContent{
		Schema: node.Schema, Type: node.Type, EntityID: node.EntityID, Parents: node.Parents,
		Payload: node.Payload, SealedPayload: node.SealedPayload, Actor: node.Actor, Role: node.Role, Command: node.Command, CreatedAt: node.CreatedAt,
		RequestID: node.RequestID, RequestHash: node.RequestHash,
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(contentBytes)
	expected := "sha256:" + hex.EncodeToString(sum[:])
	if expected != node.Hash {
		return appErr(ErrValidation, "node integrity check failed for %s", node.Hash)
	}
	return nil
}

func (s *Store) NodesFromRoot(root string) ([]Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodesFromRoot(root)
}

func (s *Store) nodesFromRoot(root string) ([]Node, error) {
	if root == "" {
		return nil, nil
	}
	var reversed []Node
	seen := map[string]bool{}
	for root != "" {
		if seen[root] {
			return nil, appErr(ErrValidation, "cycle detected while walking DAG at %s", root)
		}
		seen[root] = true
		node, err := s.readNode(root)
		if err != nil {
			return nil, err
		}
		reversed = append(reversed, node)
		if len(node.Parents) == 0 {
			break
		}
		if len(node.Parents) > 1 {
			return nil, appErr(ErrValidation, "merge roots are not supported in phase 1")
		}
		root = node.Parents[0]
	}
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	return reversed, nil
}

func (s *Store) AuditLog() ([]Node, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	root, err := s.currentRoot()
	if err != nil {
		return nil, err
	}
	return s.nodesFromRoot(root)
}

func (s *Store) NodePayload(node Node) ([]byte, error) {
	if node.SealedPayload != nil {
		return decryptPayload(s.key, node.SealedPayload)
	}
	if len(node.Payload) > 0 {
		return node.Payload, nil
	}
	return nil, appErr(ErrValidation, "node %s has no payload", node.Hash)
}

func (s *Store) WriteNamedRef(name string, root string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	name = strings.TrimSpace(name)
	root = strings.TrimSpace(root)
	if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) {
		return appErr(ErrValidation, "named ref must be a simple file-safe name")
	}
	if root == "" {
		return appErr(ErrValidation, "named ref root is required")
	}
	if _, err := s.readNode(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return appErr(ErrNotFound, "root %s does not exist", root)
		}
		return err
	}
	path := filepath.Join(s.dir, "refs", "named", name)
	return atomicWriteFile(path, []byte(root+"\n"), 0o600)
}

func (s *Store) NamedRef(name string) (string, error) {
	name = strings.TrimSpace(name)
	if err := validateRefName(name); err != nil {
		return "", err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, err := os.ReadFile(filepath.Join(s.dir, "refs", "named", name))
	if errors.Is(err, os.ErrNotExist) {
		return "", appErr(ErrNotFound, "named ref %q does not exist", name)
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func validateRefName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, `/\\`) {
		return appErr(ErrValidation, "named ref must be a simple file-safe name")
	}
	return nil
}

func validateHash(hash string) error {
	if len(hash) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(hash, "sha256:") {
		return appErr(ErrValidation, "invalid SHA-256 node hash")
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(hash, "sha256:"))
	if err != nil || len(decoded) != sha256.Size {
		return appErr(ErrValidation, "invalid SHA-256 node hash")
	}
	return nil
}

func loadOrCreateKey(dir string) ([]byte, error) {
	if raw := os.Getenv("JAYBASE_DATA_KEY"); raw != "" {
		key, err := decodeKey(raw)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	if raw := os.Getenv("INFOBASE_DATA_KEY"); raw != "" {
		key, err := decodeKey(raw)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	path := filepath.Join(dir, "keys", "data.key")
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}
		encoded := base64.StdEncoding.EncodeToString(key)
		if err := atomicWriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
			return nil, err
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	return decodeKey(strings.TrimSpace(string(b)))
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".jaybase-write-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func atomicCreateFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".jaybase-node-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func decodeKey(raw string) ([]byte, error) {
	if key, err := base64.StdEncoding.DecodeString(raw); err == nil && len(key) == 32 {
		return key, nil
	}
	if key, err := hex.DecodeString(raw); err == nil && len(key) == 32 {
		return key, nil
	}
	return nil, appErr(ErrValidation, "JAYBASE_DATA_KEY, INFOBASE_DATA_KEY, or store key must be 32 bytes encoded as base64 or hex")
}

func encryptPayload(key []byte, plaintext []byte) (*EncryptedPayload, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return &EncryptedPayload{
		Algorithm:  "AES-256-GCM",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

func decryptPayload(key []byte, sealed *EncryptedPayload) ([]byte, error) {
	if sealed.Algorithm != "AES-256-GCM" {
		return nil, appErr(ErrValidation, "unsupported payload encryption algorithm %q", sealed.Algorithm)
	}
	nonce, err := base64.StdEncoding.DecodeString(sealed.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, appErr(ErrValidation, "invalid encrypted payload nonce length")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, appErr(ErrValidation, "encrypted payload authentication failed")
	}
	return plaintext, nil
}
