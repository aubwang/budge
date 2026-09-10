package store

import (
	"crypto/cipher"
	"database/sql"
	_ "embed"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

type Store struct {
	DB    *sql.DB
	Vault cipher.AEAD
	lock  *os.File
}

func Open(path, unlock string) (s *Store, err error) {
	if len(unlock) < 12 {
		return nil, errors.New("unlock secret must have at least 12 characters")
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("database already in use")
	}
	s = &Store{lock: lock}
	opened := s
	defer func() {
		if err != nil {
			opened.Close()
		}
	}()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	if err = os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	s.DB, err = sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s.DB.SetMaxOpenConns(1)
	if _, err = s.DB.Exec("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;" + schema); err != nil {
		return nil, err
	}
	var salt, check []byte
	err = s.DB.QueryRow("SELECT value FROM metadata WHERE key='salt'").Scan(&salt)
	if err == sql.ErrNoRows {
		salt = Random(16)
		s.Vault, err = AEAD(Key(unlock, salt))
		if err != nil {
			return nil, err
		}
		tx, e := s.DB.Begin()
		if e != nil {
			return nil, e
		}
		defer tx.Rollback()
		if _, err = tx.Exec("INSERT INTO metadata(key,value) VALUES('salt',?),('check',?)", salt, Seal(s.Vault, "unlock-check", []byte("budge-v1"))); err != nil {
			return nil, err
		}
		err = tx.Commit()
	} else if err == nil {
		s.Vault, err = AEAD(Key(unlock, salt))
		if err != nil {
			return nil, err
		}
		err = s.DB.QueryRow("SELECT value FROM metadata WHERE key='check'").Scan(&check)
		if err != nil {
			return nil, err
		}
		var b []byte
		b, err = Unseal(s.Vault, "unlock-check", check)
		if err != nil || string(b) != "budge-v1" {
			return nil, errors.New("cannot unlock database")
		}
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() {
	if s.DB != nil {
		s.DB.Close()
	}
	if s.lock != nil {
		syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		s.lock.Close()
	}
}
func (s *Store) Encrypt(purpose string, b []byte) []byte          { return Seal(s.Vault, purpose, b) }
func (s *Store) Decrypt(purpose string, b []byte) ([]byte, error) { return Unseal(s.Vault, purpose, b) }
func Audit(tx *sql.Tx, owner, device, kind, entity string) error {
	_, err := tx.Exec("INSERT INTO audit(owner_id,device_id,kind,entity_id) VALUES(?,?,?,?)", owner, device, kind, entity)
	return err
}
