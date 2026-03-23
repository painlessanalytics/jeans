package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// parseHTAccess reads an Apache-compatible htpasswd file and returns a map of
// username -> bcrypt hash. Lines beginning with '#' and empty lines are ignored.
func parseHTAccess(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening htaccess file: %w", err)
	}
	defer f.Close()

	users := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		users[parts[0]] = parts[1]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading htaccess file: %w", err)
	}
	return users, nil
}

// validateCredentials checks username/password against the .htaccess file.
// Supports bcrypt hashes ($2y$, $2a$, $2b$ prefixes).
func validateCredentials(htaccessPath, username, password string) bool {
	users, err := parseHTAccess(htaccessPath)
	if err != nil {
		return false
	}
	hash, ok := users[username]
	if !ok {
		return false
	}
	// bcrypt: $2y$, $2a$, $2b$ are all accepted by Go's bcrypt package
	if strings.HasPrefix(hash, "$2") {
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		return err == nil
	}
	return false
}

// AddHTAccessUser adds or updates a user entry in the .htaccess file using bcrypt.
func AddHTAccessUser(htaccessPath, username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	// Read existing entries
	users, _ := parseHTAccess(htaccessPath) // ignore error if file doesn't exist
	if users == nil {
		users = make(map[string]string)
	}
	users[username] = string(hash)

	return writeHTAccess(htaccessPath, users)
}

func writeHTAccess(path string, users map[string]string) error {
	if err := os.MkdirAll(ConfigDir, 0750); err != nil {
		return err
	}
	var sb strings.Builder
	sb.WriteString("# Denims htpasswd file — do not edit by hand while the service is running\n")
	for u, h := range users {
		sb.WriteString(u + ":" + h + "\n")
	}
	return os.WriteFile(path, []byte(sb.String()), 0640)
}

// basicAuthMiddleware wraps an http.Handler requiring HTTP Basic Auth validated
// against the .htaccess file.
func basicAuthMiddleware(htaccessPath string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Login page itself is exempt so we can render the form
		if r.URL.Path == "/login" && r.Method == http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}

		username, password, ok := r.BasicAuth()
		if !ok || !validateCredentials(htaccessPath, username, password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Denims Account Manager"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
