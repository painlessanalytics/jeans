package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
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

// usersHandler renders the user list and handles new-user form submissions.
func usersHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			Users   []SystemUser
			Error   string
			Success string
		}{}

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
}

// deleteUserHandler handles user deletion form submissions.
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
		if err := DeleteUser(username); err != nil {
			// Redirect back with an error query param
			http.Redirect(w, r, fmt.Sprintf("/users?error=%s", template.URLQueryEscaper(err.Error())), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/users?success=User+deleted+successfully", http.StatusSeeOther)
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

// ensureHTAccess creates the .htaccess file with a default admin user if it
// does not already exist.
func ensureHTAccess(htaccessPath string) error {
	if _, err := os.Stat(htaccessPath); err == nil {
		return nil // already exists
	}

	log.Printf("denims: creating default .htaccess at %s", htaccessPath)
	log.Printf("denims: default credentials — username: admin  password: changeme")
	log.Printf("denims: IMPORTANT: change the default password immediately!")

	if err := os.MkdirAll(ConfigDir, 0750); err != nil {
		return err
	}
	return AddHTAccessUser(htaccessPath, "admin", "changeme")
}
