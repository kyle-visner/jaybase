package jaybase

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyMigrationInfo describes an offline migration to a new data key. Node
// hashes necessarily change because the ciphertext is content-addressed.
type KeyMigrationInfo struct {
	SourceRoot      string            `json:"source_root"`
	DestinationRoot string            `json:"destination_root"`
	Nodes           int               `json:"nodes"`
	NamedRefs       int               `json:"named_refs"`
	HashMap         map[string]string `json:"hash_map"`
}

// MigrateDataKey decrypts the complete source history and writes an equivalent
// history to a new, previously nonexistent directory using newEncodedKey. The
// source is held read-only for the duration. Callers must keep the service
// offline so the returned destination is a complete cutover point.
func (s *Store) MigrateDataKey(destinationDir, newEncodedKey string) (KeyMigrationInfo, error) {
	sourceAbs, err := filepath.Abs(s.dir)
	if err != nil {
		return KeyMigrationInfo{}, err
	}
	destinationAbs, err := filepath.Abs(strings.TrimSpace(destinationDir))
	if err != nil {
		return KeyMigrationInfo{}, err
	}
	if destinationAbs == sourceAbs {
		return KeyMigrationInfo{}, appErr(ErrValidation, "destination must differ from the source store")
	}
	if _, err := os.Lstat(destinationAbs); err == nil {
		return KeyMigrationInfo{}, appErr(ErrConflict, "destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return KeyMigrationInfo{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	sourceRoot, err := s.currentRoot()
	if err != nil {
		return KeyMigrationInfo{}, err
	}
	if sourceRoot != s.indexedRoot() {
		return KeyMigrationInfo{}, appErr(ErrIntegrity, "current root does not match the in-memory history index")
	}

	destination, err := OpenStoreWithDataKey(destinationAbs, newEncodedKey)
	if err != nil {
		return KeyMigrationInfo{}, fmt.Errorf("open destination store: %w", err)
	}
	defer destination.Close()

	rootMap := make(map[string]string, len(s.history))
	newRoot := ""
	for _, hash := range s.history {
		node, err := s.readNode(hash)
		if err != nil {
			return KeyMigrationInfo{}, err
		}
		payload, err := s.nodePayload(node)
		if err != nil {
			return KeyMigrationInfo{}, err
		}
		newHash, err := destination.AppendAt(Context{Actor: node.Actor, Role: node.Role}, AppendOptions{
			Type: node.Type, EntityID: node.EntityID, Command: node.Command,
			Payload: json.RawMessage(payload), CreatedAt: node.CreatedAt,
			RequestID: node.RequestID, RequestHash: node.RequestHash,
		}, newRoot)
		if err != nil {
			return KeyMigrationInfo{}, err
		}
		rootMap[hash] = newHash
		newRoot = newHash
	}

	refs, err := os.ReadDir(filepath.Join(s.dir, "refs", "named"))
	if err != nil {
		return KeyMigrationInfo{}, err
	}
	namedRefs := 0
	for _, entry := range refs {
		if !entry.Type().IsRegular() {
			return KeyMigrationInfo{}, appErr(ErrIntegrity, "named ref %q is not a regular file", entry.Name())
		}
		raw, err := os.ReadFile(filepath.Join(s.dir, "refs", "named", entry.Name()))
		if err != nil {
			return KeyMigrationInfo{}, err
		}
		mapped, ok := rootMap[strings.TrimSpace(string(raw))]
		if !ok {
			return KeyMigrationInfo{}, appErr(ErrIntegrity, "named ref %q points outside the current history", entry.Name())
		}
		if err := destination.WriteNamedRefAt(entry.Name(), mapped, ""); err != nil {
			return KeyMigrationInfo{}, err
		}
		namedRefs++
	}

	return KeyMigrationInfo{
		SourceRoot: sourceRoot, DestinationRoot: newRoot,
		Nodes: len(s.history), NamedRefs: namedRefs, HashMap: rootMap,
	}, nil
}
