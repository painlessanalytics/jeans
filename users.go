package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SystemUser represents a Linux user account.
type SystemUser struct {
	Username string
	HomeDir  string
	Shell    string
}

// ListUsers returns users that have a directory under homeBase (/home).
// It cross-references /etc/passwd to get the shell.
func ListUsers(homeBase string) ([]SystemUser, error) {
	entries, err := os.ReadDir(homeBase)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", homeBase, err)
	}

	// Build a quick lookup from /etc/passwd for shell info
	passwdMap := buildPasswdMap()

	var users []SystemUser
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		home := filepath.Join(homeBase, name)
		shell := ""
		if info, ok := passwdMap[name]; ok {
			shell = info.shell
		}
		users = append(users, SystemUser{
			Username: name,
			HomeDir:  home,
			Shell:    shell,
		})
	}
	return users, nil
}

type passwdEntry struct {
	shell string
}

func buildPasswdMap() map[string]passwdEntry {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	m := make(map[string]passwdEntry)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		m[fields[0]] = passwdEntry{shell: fields[6]}
	}
	return m
}

// AddUser creates a new system user with a home directory.
// password must be the plain-text password; it is hashed via chpasswd.
func AddUser(username, password string) error {
	if err := validateUsername(username); err != nil {
		return err
	}

	// useradd -m creates the home directory
	cmd := exec.Command("useradd", "-m", "-s", "/bin/bash", username)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("useradd failed: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Set the password via chpasswd (reads "user:password" from stdin)
	chpasswd := exec.Command("chpasswd")
	chpasswd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s", username, password))
	chpasswd.Stdout = os.Stderr
	chpasswd.Stderr = os.Stderr
	if out, err := chpasswd.CombinedOutput(); err != nil {
		return fmt.Errorf("chpasswd failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// DeleteUser removes a system user and their home directory.
func DeleteUser(username string) error {
	if err := validateUsername(username); err != nil {
		return err
	}

	// -r removes the home directory and mail spool
	cmd := exec.Command("userdel", "-r", username)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("userdel failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// validateUsername enforces basic sanity checks to prevent shell injection.
func validateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username must not be empty")
	}
	if len(username) > 32 {
		return fmt.Errorf("username too long (max 32 characters)")
	}
	for _, c := range username {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			return fmt.Errorf("username contains invalid character: %q", c)
		}
	}
	// Prevent operating on system-critical users
	reserved := map[string]bool{
		"root": true, "daemon": true, "bin": true, "sys": true,
		"sync": true, "games": true, "man": true, "lp": true,
		"mail": true, "news": true, "uucp": true, "proxy": true,
		"www-data": true, "backup": true, "list": true, "irc": true,
		"nobody": true,
	}
	if reserved[username] {
		return fmt.Errorf("cannot manage reserved system user: %q", username)
	}
	return nil
}
