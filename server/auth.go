package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type Role int

const (
	RoleReader Role = iota + 1
	RoleWriter
	RoleAdmin
)

func (r Role) String() string {
	switch r {
	case RoleReader:
		return "reader"
	case RoleWriter:
		return "writer"
	case RoleAdmin:
		return "admin"
	default:
		return "unknown"
	}
}

func parseRole(raw string) (Role, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "reader":
		return RoleReader, nil
	case "writer":
		return RoleWriter, nil
	case "admin":
		return RoleAdmin, nil
	default:
		return 0, fmt.Errorf("role must be reader, writer, or admin")
	}
}

type Principal struct {
	ID   string
	Role Role
}

type credentialFile struct {
	Tokens []credentialRecord `json:"tokens"`
}

type credentialRecord struct {
	ID     string `json:"id"`
	Role   string `json:"role"`
	SHA256 string `json:"sha256"`
}

type credential struct {
	principal Principal
	digest    [sha256.Size]byte
}

type Authenticator struct {
	credentials []credential
}

func LoadAuthenticator(path string) (*Authenticator, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read auth file: %w", err)
	}
	var file credentialFile
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode auth file: %w", err)
	}
	if len(file.Tokens) == 0 {
		return nil, fmt.Errorf("auth file must contain at least one token")
	}

	seen := make(map[string]bool, len(file.Tokens))
	seenDigests := make(map[[sha256.Size]byte]bool, len(file.Tokens))
	auth := &Authenticator{credentials: make([]credential, 0, len(file.Tokens))}
	for i, record := range file.Tokens {
		record.ID = strings.TrimSpace(record.ID)
		if !validCredentialID(record.ID) {
			return nil, fmt.Errorf("tokens[%d].id must use 1-128 letters, digits, dots, colons, underscores, at signs, or hyphens", i)
		}
		if seen[record.ID] {
			return nil, fmt.Errorf("duplicate credential id %q", record.ID)
		}
		seen[record.ID] = true
		role, err := parseRole(record.Role)
		if err != nil {
			return nil, fmt.Errorf("tokens[%d]: %w", i, err)
		}
		digest, err := hex.DecodeString(strings.TrimSpace(record.SHA256))
		if err != nil || len(digest) != sha256.Size {
			return nil, fmt.Errorf("tokens[%d].sha256 must be a 64-character SHA-256 hex digest", i)
		}
		var fixed [sha256.Size]byte
		copy(fixed[:], digest)
		if seenDigests[fixed] {
			return nil, fmt.Errorf("tokens[%d] duplicates another token digest", i)
		}
		seenDigests[fixed] = true
		auth.credentials = append(auth.credentials, credential{
			principal: Principal{ID: record.ID, Role: role},
			digest:    fixed,
		})
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("auth file must contain exactly one JSON object")
	}
	return auth, nil
}

func validCredentialID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, char := range id {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("._:@-", char) {
			continue
		}
		return false
	}
	return true
}

func (a *Authenticator) Authenticate(token string) (Principal, bool) {
	if len(token) < 32 || len(token) > 512 {
		return Principal{}, false
	}
	digest := sha256.Sum256([]byte(token))
	var matched Principal
	found := 0
	for _, candidate := range a.credentials {
		equal := subtle.ConstantTimeCompare(digest[:], candidate.digest[:])
		if equal == 1 {
			matched = candidate.principal
		}
		found |= equal
	}
	return matched, found == 1
}
