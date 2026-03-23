// denims-passwd — manage credentials in the denims .htaccess file.
//
// Usage:
//
//	denims-passwd <username> <password>   — add or update a user
//	denims-passwd -d <username>           — delete a user
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const htaccessPath = "/var/denims/config/.htaccess"

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	if args[0] == "-d" {
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: denims-passwd -d <username>")
			os.Exit(1)
		}
		if err := deleteUser(args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("User %q removed from %s\n", args[1], htaccessPath)
		return
	}

	if len(args) != 2 {
		usage()
		os.Exit(1)
	}

	username, password := args[0], args[1]
	if err := addOrUpdateUser(username, password); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("User %q updated in %s\n", username, htaccessPath)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: denims-passwd <username> <password>")
	fmt.Fprintln(os.Stderr, "       denims-passwd -d <username>")
}

func readHTAccess() (map[string]string, error) {
	f, err := os.Open(htaccessPath)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]string), nil
		}
		return nil, err
	}
	defer f.Close()

	users := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			users[parts[0]] = parts[1]
		}
	}
	return users, sc.Err()
}

func writeHTAccess(users map[string]string) error {
	if err := os.MkdirAll("/var/denims/config", 0750); err != nil {
		return err
	}
	var sb strings.Builder
	sb.WriteString("# Denims htpasswd file\n")
	for u, h := range users {
		sb.WriteString(u + ":" + h + "\n")
	}
	return os.WriteFile(htaccessPath, []byte(sb.String()), 0640)
}

func addOrUpdateUser(username, password string) error {
	users, err := readHTAccess()
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	users[username] = string(hash)
	return writeHTAccess(users)
}

func deleteUser(username string) error {
	users, err := readHTAccess()
	if err != nil {
		return err
	}
	if _, ok := users[username]; !ok {
		return fmt.Errorf("user %q not found in %s", username, htaccessPath)
	}
	delete(users, username)
	return writeHTAccess(users)
}
