package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
)


func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("denims: loading config: %v", err)
	}

	// Ensure the TLS certificate exists (generate self-signed if missing)
	if err := ensureTLSCert(cfg.TLSCert, cfg.TLSKey); err != nil {
		log.Fatalf("denims: TLS cert setup: %v", err)
	}

	// Ensure the .htaccess file exists
	if err := ensureHTAccess(cfg.HTAccessPath); err != nil {
		log.Fatalf("denims: htaccess setup: %v", err)
	}

	// Load (or generate) the JWT signing secret
	secret, err := cfg.jwtSecretBytes()
	if err != nil {
		log.Fatalf("denims: JWT secret: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/users", http.StatusFound)
	})
	mux.HandleFunc("/login", loginHandler(cfg, secret))
	mux.HandleFunc("/logout", logoutHandler())
	mux.HandleFunc("/users", usersHandler(cfg))
	mux.HandleFunc("/users/delete", deleteUserHandler(cfg))

	handler := jwtMiddleware(secret, mux)

	addr := fmt.Sprintf(":%d", cfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
			PreferServerCipherSuites: true,
		},
	}

	log.Printf("denims: listening on https://0.0.0.0%s", addr)
	if err := srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil {
		log.Fatalf("denims: server error: %v", err)
	}
}

// usersPage is the view model for the users template.
type usersPage struct {
	Users   []SystemUser
	Error   string
	Success string
}

// renderUsers fills in the user list and renders the users page.
func renderUsers(w http.ResponseWriter, cfg *Config, data usersPage) {
	users, err := ListUsers(cfg.HomeDir)
	if err != nil {
		data.Error = fmt.Sprintf("Failed to list users: %v", err)
	}
	data.Users = users

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := executeTemplate(w, tmplUsers, data); err != nil {
		log.Printf("denims: template error: %v", err)
	}
}

// usersHandler renders the user list and handles new-user form submissions.
func usersHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var data usersPage

		switch r.Method {
		case http.MethodGet:
			// fall through to render

		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				data.Error = "Invalid form data."
				break
			}
			username := r.FormValue("username")
			password := r.FormValue("password")

			if err := AddUser(username, password); err != nil {
				data.Error = fmt.Sprintf("Failed to add user: %v", err)
			} else {
				data.Success = fmt.Sprintf("User %q created successfully.", username)
			}

		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		renderUsers(w, cfg, data)
	}
}

// deleteUserHandler handles user deletion form submissions. The result is
// rendered directly (rather than via a redirect with message query params) so
// that the outcome is always shown and arbitrary text can't be injected into
// the page through a crafted URL.
func deleteUserHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		username := r.FormValue("username")

		var data usersPage
		if err := DeleteUser(cfg.HomeDir, username); err != nil {
			data.Error = fmt.Sprintf("Failed to delete user: %v", err)
		} else {
			data.Success = fmt.Sprintf("User %q deleted successfully.", username)
		}
		renderUsers(w, cfg, data)
	}
}

// executeTemplate executes a template that embeds "layout" and "content" together.
func executeTemplate(w http.ResponseWriter, t *template.Template, data interface{}) error {
	return t.ExecuteTemplate(w, "layout", data)
}

// ensureTLSCert generates a self-signed ECDSA P-256 certificate if the cert or
// key files are absent.
func ensureTLSCert(certPath, keyPath string) error {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if certErr == nil && keyErr == nil {
		return nil // both exist
	}

	log.Printf("denims: generating self-signed TLS certificate at %s", certPath)

	if err := os.MkdirAll(ConfigDir, 0750); err != nil {
		return err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generating serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Denims Account Manager"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	// Write certificate
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("opening cert file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	// Write private key
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("opening key file: %w", err)
	}
	defer keyOut.Close()
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshaling key: %w", err)
	}
	return pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
}

// ensureHTAccess makes sure the .htaccess file exists. On first run it creates
// an "admin" user with a randomly generated password, written to a root-only
// file (never to the logs). On later runs it warns if the legacy hard-coded
// default password is still in use.
func ensureHTAccess(htaccessPath string) error {
	if _, err := os.Stat(htaccessPath); err == nil {
		warnIfLegacyDefaultPassword(htaccessPath)
		return nil // already exists
	}

	if err := os.MkdirAll(ConfigDir, 0750); err != nil {
		return err
	}

	password, err := randomPassword()
	if err != nil {
		return fmt.Errorf("generating admin password: %w", err)
	}

	// Write the plaintext password where only root can read it, before creating
	// .htaccess, so a crash in between can't leave an account nobody knows the
	// password to.
	if err := os.WriteFile(InitialPasswordFile, []byte("admin:"+password+"\n"), 0600); err != nil {
		return fmt.Errorf("writing initial password file: %w", err)
	}
	if err := AddHTAccessUser(htaccessPath, "admin", password); err != nil {
		return err
	}

	log.Printf("denims: created %s with user %q", htaccessPath, "admin")
	log.Printf("denims: generated initial password saved to %s (readable by root only)", InitialPasswordFile)
	log.Printf("denims: sign in, then run `denims-passwd admin <new-password>` and delete that file")
	return nil
}

// randomPassword returns a 128-bit random password, URL-safe base64 encoded.
func randomPassword() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// warnIfLegacyDefaultPassword logs a warning when an admin account still uses
// the old hard-coded "changeme" password from earlier versions.
func warnIfLegacyDefaultPassword(htaccessPath string) {
	users, err := parseHTAccess(htaccessPath)
	if err != nil {
		return
	}
	for name, hash := range users {
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte("changeme")) == nil {
			log.Printf("denims: WARNING: user %q still has the default password %q — change it now with `denims-passwd %s <new-password>`", name, "changeme", name)
		}
	}
}
