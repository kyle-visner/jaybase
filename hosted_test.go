package jaybase

import (
	"archive/tar"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestAppendAtSerializesConcurrentWriters(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	const writers = 24
	start := make(chan struct{})
	results := make(chan error, writers)
	var group sync.WaitGroup
	for i := 0; i < writers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := store.AppendAt(Context{Actor: "writer", Role: "writer"}, AppendOptions{
				Type: "fact", Command: "fact create", Payload: map[string]bool{"ok": true},
			}, "")
			results <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)

	succeeded, conflicted := 0, 0
	for err := range results {
		if err == nil {
			succeeded++
			continue
		}
		var app *AppError
		if errors.As(err, &app) && app.Code == ErrConflict {
			conflicted++
			continue
		}
		t.Fatalf("unexpected append error: %v", err)
	}
	if succeeded != 1 || conflicted != writers-1 {
		t.Fatalf("expected one success and %d conflicts, got %d and %d", writers-1, succeeded, conflicted)
	}
}

func TestAppendIdempotentSurvivesNewerEvents(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, replayed, err := store.AppendIdempotent(Context{Actor: "agent"}, AppendOptions{
		Type: "fact", Command: "remember", Payload: map[string]string{"value": "one"},
	}, "", "request-one", "content-one")
	if err != nil || replayed {
		t.Fatalf("first append: replayed=%v err=%v", replayed, err)
	}
	second, err := store.AppendAt(Context{Actor: "agent"}, AppendOptions{
		Type: "fact", Command: "remember", Payload: map[string]string{"value": "two"},
	}, first)
	if err != nil {
		t.Fatal(err)
	}
	retried, replayed, err := store.AppendIdempotent(Context{Actor: "agent"}, AppendOptions{
		Type: "fact", Command: "remember", Payload: map[string]string{"value": "one"},
	}, "", "request-one", "content-one")
	if err != nil || !replayed || retried != first {
		t.Fatalf("retry: hash=%q replayed=%v err=%v", retried, replayed, err)
	}
	root, err := store.CurrentRoot()
	if err != nil || root != second {
		t.Fatalf("retry changed current root: root=%q err=%v", root, err)
	}
}

func TestSnapshotExcludesKeysAndPlaintext(t *testing.T) {
	storeDir := t.TempDir()
	store, err := OpenStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	secret := "snapshot-must-not-contain-this-plaintext"
	if _, err := store.Append(Context{Actor: "agent"}, AppendOptions{
		Type: "fact", Command: "remember", Payload: map[string]string{"secret": secret},
	}); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "snapshot.tar.gz")
	if _, err := store.Snapshot(dest); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	seenManifest, seenRoot, seenNode := false, false, false
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(header.Name, "keys/") {
			t.Fatalf("snapshot included key path %q", header.Name)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), secret) {
			t.Fatalf("snapshot entry %q contains plaintext payload", header.Name)
		}
		switch {
		case header.Name == "manifest.json":
			seenManifest = true
		case header.Name == "refs/root":
			seenRoot = true
		case strings.HasPrefix(header.Name, "objects/nodes/"):
			seenNode = true
		}
	}
	if !seenManifest || !seenRoot || !seenNode {
		t.Fatalf("incomplete snapshot: manifest=%v root=%v node=%v", seenManifest, seenRoot, seenNode)
	}

	keyBytes, err := os.ReadFile(filepath.Join(storeDir, "keys", "data.key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyBytes))); err != nil {
		t.Fatalf("local test key should remain separately recoverable: %v", err)
	}
}

func TestNodePayloadRejectsBadNonceWithoutPanicking(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	node := Node{Hash: "sha256:" + strings.Repeat("0", 64), SealedPayload: &EncryptedPayload{
		Algorithm: "AES-256-GCM", Nonce: base64.StdEncoding.EncodeToString([]byte("short")),
		Ciphertext: base64.StdEncoding.EncodeToString([]byte("ciphertext")),
	}}
	if _, err := store.NodePayload(node); err == nil {
		t.Fatal("expected invalid nonce to be rejected")
	}
}

func TestVerifyHeadRejectsMisaddressedNode(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Append(Context{Actor: "agent"}, AppendOptions{
		Type: "fact", Command: "remember", Payload: map[string]int{"value": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Append(Context{Actor: "agent"}, AppendOptions{
		Type: "fact", Command: "remember", Payload: map[string]int{"value": 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(store.NodePath(first))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.NodePath(second), firstBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyHead(); err == nil {
		t.Fatal("expected a node stored under the wrong address to fail readiness")
	}
}
