package main

import "testing"

func TestValidateUsername(t *testing.T) {
	bad := []string{"", "-f", "--force", "a b", "a:b", "root", "x\nroot", "waytoolongusernamewaytoolongusername"}
	for _, u := range bad {
		if validateUsername(u) == nil {
			t.Errorf("validateUsername(%q) = nil, want error", u)
		}
	}
	for _, u := range []string{"jsmith", "J_Smith-1", "a.b"} {
		if err := validateUsername(u); err != nil {
			t.Errorf("validateUsername(%q) = %v, want nil", u, err)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	bad := []string{"", "short", "longenough\nroot:pwned", "longenough\rx", "longenough\x00"}
	for _, p := range bad {
		if validatePassword(p) == nil {
			t.Errorf("validatePassword(%q) = nil, want error", p)
		}
	}
	if err := validatePassword("correct horse"); err != nil {
		t.Errorf("validatePassword rejected a valid password: %v", err)
	}
}

func TestDeleteUserRefusesSystemAccounts(t *testing.T) {
	// These exist on any Linux box with uid < 1000 (or are reserved names);
	// DeleteUser must refuse before ever invoking userdel.
	for _, u := range []string{"root", "sshd", "systemd-network", "nonexistent-user-xyz"} {
		if err := DeleteUser("/home", u); err == nil {
			t.Errorf("DeleteUser(%q) = nil, want error", u)
		}
	}
}
