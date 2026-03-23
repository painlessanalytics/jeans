package main

import (
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
	Port        int    `json:"port"`
	TLSCert     string `json:"tls_cert"`
	TLSKey      string `json:"tls_key"`
	HTAccessPath string `json:"htaccess_path"`
	HomeDir     string `json:"home_dir"`
}

func defaultConfig() *Config {
	return &Config{
		Port:        501,
		TLSCert:     TLSCertFile,
		TLSKey:      TLSKeyFile,
		HTAccessPath: HTAccessFile,
		HomeDir:     HomeDir,
	}
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
