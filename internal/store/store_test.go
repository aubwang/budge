package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDatabaseLockUsesFileIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "budge.db")
	s, e := Open(path, "synthetic-unlock-password")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	alias := filepath.Join(dir, "alias.db")
	if e = os.Link(path, alias); e != nil {
		t.Fatal(e)
	}
	if other, e := Open(alias, "synthetic-unlock-password"); e == nil {
		other.Close()
		t.Fatal("hardlink bypassed startup lock")
	} else if !strings.Contains(e.Error(), "already in use") {
		t.Fatal(e)
	}
}
