package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// Regular (non-system) accounts on Ubuntu start at UID 1000; 65534 is nobody
	// and anything at or above 60000 is reserved by Debian policy.
	minManagedUID = 1000
	maxManagedUID = 59999

	minPasswordLen = 8
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
	uid   int
	home  string
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
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		m[fields[0]] = passwdEntry{uid: uid, home: fields[5], shell: fields[6]}
	}
	return m
}

// AddUser creates a new system user with a home directory.
// password must be the plain-text password; it is hashed via chpasswd.
func AddUser(username, password string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	if err := validatePassword(password); err != nil {
		return err
	}

	// useradd -m creates the home directory. "--" stops option parsing so the
	// username can never be interpreted as a flag.
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", "--", username).CombinedOutput(); err != nil {
		return fmt.Errorf("useradd failed: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Set the password via chpasswd (reads "user:password" from stdin)
	chpasswd := exec.Command("chpasswd")
	chpasswd.Stdin = strings.NewReader(username + ":" + password + "\n")
	if out, err := chpasswd.CombinedOutput(); err != nil {
		// Don't leave a half-created account behind.
		if rbOut, rbErr := exec.Command("userdel", "-r", "--", username).CombinedOutput(); rbErr != nil {
			return fmt.Errorf("chpasswd failed: %s: %w (rollback also failed: %s)",
				strings.TrimSpace(string(out)), err, strings.TrimSpace(string(rbOut)))
		}
		return fmt.Errorf("chpasswd failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// DeleteUser removes a system user and their home directory. Only regular
// accounts (UID in the managed range) whose home directory lives directly
// under homeBase may be deleted.
func DeleteUser(homeBase, username string) error {
	if err := validateUsername(username); err != nil {
		return err
	}

	entry, ok := buildPasswdMap()[username]
	if !ok {
		return fmt.Errorf("user %q does not exist", username)
	}
	if entry.uid < minManagedUID || entry.uid > maxManagedUID {
		return fmt.Errorf("cannot manage system account %q (uid %d)", username, entry.uid)
	}
	if filepath.Dir(filepath.Clean(entry.home)) != filepath.Clean(homeBase) {
		return fmt.Errorf("user %q has home %q outside %s", username, entry.home, homeBase)
	}

	// -r removes the home directory and mail spool
	if out, err := exec.Command("userdel", "-r", "--", username).CombinedOutput(); err != nil {
		return fmt.Errorf("userdel failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// validatePassword rejects passwords that are too short or that could break
// the "user:password" line format consumed by chpasswd.
func validatePassword(password string) error {
	if len(password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	if strings.ContainsAny(password, "\r\n\x00") {
		return fmt.Errorf("password must not contain line breaks or NUL characters")
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
	// A leading '-' would be parsed as a command-line option.
	if username[0] == '-' {
		return fmt.Errorf("username must not start with '-'")
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
