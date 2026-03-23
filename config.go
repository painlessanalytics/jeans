package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	ConfigDir     = "/var/denims/config"
	ConfigFile    = "/var/denims/config/config.json"
	HTAccessFile  = "/var/denims/config/.htaccess"
	TLSCertFile   = "/var/denims/config/server.crt"
	TLSKeyFile    = "/var/denims/config/server.key"
	HomeDir       = "/home"
)

// Config holds application configuration loaded from config.json.
type Config struct {
	Port         int    `json:"port"`
	TLSCert      string `json:"tls_cert"`
	TLSKey       string `json:"tls_key"`
	HTAccessPath string `json:"htaccess_path"`
	HomeDir      string `json:"home_dir"`
	// JWTSecret is a base64-encoded 32-byte random key used to sign session tokens.
	// Auto-generated on first start if empty.
	JWTSecret string `json:"jwt_secret"`
}

func defaultConfig() *Config {
	return &Config{
		Port:         501,
		TLSCert:      TLSCertFile,
		TLSKey:       TLSKeyFile,
		HTAccessPath: HTAccessFile,
		HomeDir:      HomeDir,
	}
}

// jwtSecretBytes decodes the base64 JWTSecret field, generating and persisting
// a new random key when the field is empty.
func (c *Config) jwtSecretBytes() ([]byte, error) {
	if c.JWTSecret == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generating JWT secret: %w", err)
		}
		c.JWTSecret = base64.StdEncoding.EncodeToString(key)
		if err := saveConfig(c); err != nil {
			return nil, fmt.Errorf("persisting JWT secret: %w", err)
		}
	}
	key, err := base64.StdEncoding.DecodeString(c.JWTSecret)
	if err != nil {
		return nil, fmt.Errorf("decoding JWT secret: %w", err)
	}
	return key, nil
}

func loadConfig() (*Config, error) {
	cfg := defaultConfig()

	data, err := os.ReadFile(ConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Write defaults so the admin can see the file
			if werr := saveConfig(cfg); werr != nil {
				fmt.Fprintf(os.Stderr, "warning: could not write default config: %v\n", werr)
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return cfg, nil
}

func saveConfig(cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(ConfigFile), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigFile, data, 0640)
}
