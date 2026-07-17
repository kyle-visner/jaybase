package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	jaybase "github.com/kyle-visner/jaybase"
	"github.com/kyle-visner/jaybase/server"
)

func main() {
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	var err error
	switch command {
	case "serve":
		err = serve()
	case "healthcheck":
		err = healthcheck()
	case "hash-token":
		err = hashToken()
	case "init":
		err = initSecrets()
	default:
		err = fmt.Errorf("unknown command %q (expected serve, healthcheck, hash-token, or init)", command)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "jaybase-server:", err)
		os.Exit(1)
	}
}

func serve() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	dataDir := envOr("JAYBASE_DATA_DIR", ".jaybase")
	authFile := strings.TrimSpace(os.Getenv("JAYBASE_AUTH_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("JAYBASE_DATA_KEY_FILE"))
	if authFile == "" {
		return fmt.Errorf("JAYBASE_AUTH_FILE is required")
	}
	if keyFile == "" {
		return fmt.Errorf("JAYBASE_DATA_KEY_FILE is required; hosted mode never stores its key with the data")
	}
	encodedKey, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("read JAYBASE_DATA_KEY_FILE: %w", err)
	}
	store, err := jaybase.OpenStoreWithDataKey(dataDir, strings.TrimSpace(string(encodedKey)))
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	auth, err := server.LoadAuthenticator(authFile)
	if err != nil {
		return err
	}
	api, err := server.New(server.Options{
		Store: store, Auth: auth, BackupDir: strings.TrimSpace(os.Getenv("JAYBASE_BACKUP_DIR")), Logger: logger,
	})
	if err != nil {
		return err
	}
	address := envOr("JAYBASE_LISTEN_ADDR", "127.0.0.1:8080")
	httpServer := &http.Server{
		Addr: address, Handler: api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
	}()

	logger.Info("jaybase ready", "address", address, "data_dir", dataDir,
		"backups_enabled", strings.TrimSpace(os.Getenv("JAYBASE_BACKUP_DIR")) != "")
	err = httpServer.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func healthcheck() error {
	url := "http://127.0.0.1:8080/health/ready"
	if len(os.Args) > 2 {
		url = os.Args[2]
	}
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("health check returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func hashToken() error {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return err
	}
	if stat.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprint(os.Stderr, "Token: ")
	}
	token, err := bufio.NewReader(io.LimitReader(os.Stdin, 1025)).ReadString('\n')
	if err != nil && err != io.EOF {
		return err
	}
	token = strings.TrimSpace(token)
	if len(token) < 32 {
		return fmt.Errorf("token must be at least 32 characters")
	}
	sum := sha256.Sum256([]byte(token))
	fmt.Println(hex.EncodeToString(sum[:]))
	return nil
}

func initSecrets() error {
	dir := "secrets"
	if len(os.Args) > 2 {
		dir = os.Args[2]
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	for _, name := range []string{"data_key", "auth.json"} {
		path := filepath.Join(dir, name)
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	key, err := randomDataKey()
	if err != nil {
		return err
	}
	if err := createSecretFile(filepath.Join(dir, "data_key"), []byte(key+"\n")); err != nil {
		return err
	}

	type generatedCredential struct {
		ID     string `json:"id"`
		Role   string `json:"role"`
		SHA256 string `json:"sha256"`
	}
	credentials := make([]generatedCredential, 0, 3)
	plaintext := make(map[string]string, 3)
	for _, role := range []string{"admin", "writer", "reader"} {
		token, err := randomToken()
		if err != nil {
			return err
		}
		id := role + "-initial"
		sum := sha256.Sum256([]byte(token))
		credentials = append(credentials, generatedCredential{
			ID: id, Role: role, SHA256: hex.EncodeToString(sum[:]),
		})
		plaintext[id] = token
	}
	authJSON, err := json.MarshalIndent(map[string]any{"tokens": credentials}, "", "  ")
	if err != nil {
		return err
	}
	if err := createSecretFile(filepath.Join(dir, "auth.json"), append(authJSON, '\n')); err != nil {
		return err
	}
	fmt.Printf("Secrets created in %s. Store these tokens in a password manager; they are not written to disk:\n", dir)
	for _, id := range []string{"admin-initial", "writer-initial", "reader-initial"} {
		fmt.Printf("%s=%s\n", id, plaintext[id])
	}
	return nil
}

func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func randomDataKey() (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func createSecretFile(path string, contents []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s (refusing to overwrite): %w", path, err)
	}
	if _, err := f.Write(contents); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
