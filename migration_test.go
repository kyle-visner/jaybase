package jaybase

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMigrateDataKeyReencryptsHistoryAndNamedRefs(t *testing.T) {
	oldKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("o", 32)))
	newKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("n", 32)))
	source, err := OpenStoreWithDataKey(t.TempDir(), oldKey)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	created := time.Date(2026, 7, 20, 12, 0, 0, 123000, time.UTC)
	first, err := source.AppendAt(Context{Actor: "writer-1", Role: "writer"}, AppendOptions{
		Type: "fact", EntityID: "opaque-1", Command: "remember",
		Payload: map[string]string{"secret": "first"}, CreatedAt: created,
		RequestID: "request-1", RequestHash: "content-1",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := source.AppendAt(Context{Actor: "writer-2", Role: "writer"}, AppendOptions{
		Type: "fact", EntityID: "opaque-2", Command: "remember",
		Payload: map[string]string{"secret": "second"}, CreatedAt: created.Add(time.Second),
	}, first)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.WriteNamedRefAt("projection", first, ""); err != nil {
		t.Fatal(err)
	}

	destinationDir := filepath.Join(t.TempDir(), "migrated")
	info, err := source.MigrateDataKey(destinationDir, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if info.SourceRoot != second || info.DestinationRoot == "" || info.DestinationRoot == second || info.Nodes != 2 || info.NamedRefs != 1 {
		t.Fatalf("unexpected migration result: %#v", info)
	}
	if info.HashMap[first] == "" || info.HashMap[second] != info.DestinationRoot {
		t.Fatalf("incomplete hash translation map: %#v", info.HashMap)
	}

	destination, err := OpenStoreWithDataKey(destinationDir, newKey)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	root, nodes, err := destination.VerifyAll()
	if err != nil || root != info.DestinationRoot || nodes != 2 {
		t.Fatalf("destination verification: root=%q nodes=%d err=%v", root, nodes, err)
	}
	audit, err := destination.AuditLog()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := destination.NodePayload(audit[0])
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(payload, &decoded); err != nil || decoded["secret"] != "first" {
		t.Fatalf("migrated payload=%s err=%v", payload, err)
	}
	if audit[0].Actor != "writer-1" || audit[0].EntityID != "opaque-1" || !audit[0].CreatedAt.Equal(created) {
		t.Fatalf("metadata changed during migration: %#v", audit[0])
	}
	ref, err := destination.NamedRef("projection")
	if err != nil || ref != audit[0].Hash {
		t.Fatalf("migrated named ref=%q want=%q err=%v", ref, audit[0].Hash, err)
	}
}

func TestContainsRootDetectsMissingHistoryPin(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root, err := store.Append(Context{Actor: "writer"}, AppendOptions{Type: "fact", Command: "remember", Payload: true})
	if err != nil {
		t.Fatal(err)
	}
	if present, err := store.ContainsRoot(root); err != nil || !present {
		t.Fatalf("live root absent: present=%v err=%v", present, err)
	}
	missing := "sha256:" + strings.Repeat("0", 64)
	if present, err := store.ContainsRoot(missing); err != nil || present {
		t.Fatalf("missing root present: present=%v err=%v", present, err)
	}
}
