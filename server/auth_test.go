package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatorEnforcesNotAfter(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	activeToken := strings.Repeat("a", 64)
	expiredToken := strings.Repeat("e", 64)
	record := func(id, token string, notAfter time.Time) map[string]any {
		sum := sha256.Sum256([]byte(token))
		return map[string]any{
			"id": id, "role": "reader", "sha256": hex.EncodeToString(sum[:]), "not_after": notAfter,
		}
	}
	contents, err := json.Marshal(map[string]any{"tokens": []any{
		record("active", activeToken, now.Add(time.Minute)),
		record("expired", expiredToken, now),
	}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := LoadAuthenticator(path)
	if err != nil {
		t.Fatal(err)
	}
	auth.now = func() time.Time { return now }
	if principal, ok := auth.Authenticate(activeToken); !ok || principal.ID != "active" {
		t.Fatalf("active credential rejected: principal=%#v ok=%v", principal, ok)
	}
	if _, ok := auth.Authenticate(expiredToken); ok {
		t.Fatal("credential remained valid at its not_after boundary")
	}
}

func TestAddAndRevokeTokenUpdateAuthFileWithoutPlaintext(t *testing.T) {
	initial := strings.Repeat("i", 64)
	sum := sha256.Sum256([]byte(initial))
	path := filepath.Join(t.TempDir(), "auth.json")
	contents := []byte(`{"tokens":[{"id":"initial","role":"admin","sha256":"` + hex.EncodeToString(sum[:]) + `"}]}`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AddToken(path, "duplicate-token", "reader", initial, nil); err == nil {
		t.Fatal("expected duplicate token digest to be rejected")
	}
	unchanged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != string(contents) {
		t.Fatalf("duplicate digest changed auth file: %s", unchanged)
	}
	if _, err := LoadAuthenticator(path); err != nil {
		t.Fatalf("duplicate rejection left auth file unloadable: %v", err)
	}
	added := strings.Repeat("n", 64)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	if err := AddToken(path, "reader-agent", "reader", added, &expires); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), added) || !strings.Contains(string(raw), `"not_after":`) {
		t.Fatalf("unexpected auth file contents: %s", raw)
	}
	auth, err := LoadAuthenticator(path)
	if err != nil {
		t.Fatal(err)
	}
	auth.now = func() time.Time { return expires.Add(-time.Second) }
	if principal, ok := auth.Authenticate(added); !ok || principal.ID != "reader-agent" {
		t.Fatalf("added credential unavailable: principal=%#v ok=%v", principal, ok)
	}
	if err := RevokeToken(path, "initial"); err != nil {
		t.Fatal(err)
	}
	auth, err = LoadAuthenticator(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := auth.Authenticate(initial); ok {
		t.Fatal("revoked credential remained available")
	}
	if err := RevokeToken(path, "reader-agent"); err == nil {
		t.Fatal("expected final credential revocation to be refused")
	}
}

func TestRevokeTokenRefusesToLeaveOnlyExpiredCredentials(t *testing.T) {
	activeToken := strings.Repeat("a", 64)
	expiredToken := strings.Repeat("e", 64)
	digest := func(token string) string {
		sum := sha256.Sum256([]byte(token))
		return hex.EncodeToString(sum[:])
	}
	expired := time.Now().UTC().Add(-time.Hour)
	contents, err := json.Marshal(map[string]any{"tokens": []any{
		map[string]any{"id": "expired", "role": "admin", "sha256": digest(expiredToken), "not_after": expired},
		map[string]any{"id": "active", "role": "admin", "sha256": digest(activeToken)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RevokeToken(path, "active"); err == nil || !strings.Contains(err.Error(), "final active credential") {
		t.Fatalf("last-active revocation error = %v", err)
	}
	auth, err := LoadAuthenticator(path)
	if err != nil {
		t.Fatal(err)
	}
	if principal, ok := auth.Authenticate(activeToken); !ok || principal.ID != "active" {
		t.Fatalf("active credential lost after refused revoke: principal=%#v ok=%v", principal, ok)
	}
}
