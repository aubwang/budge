package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/argon2"
)

func Random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
func ID(prefix string) string { return prefix + base64.RawURLEncoding.EncodeToString(Random(18)) }
func Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func Key(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
}
func Password(password string) string {
	s := Random(16)
	return base64.RawStdEncoding.EncodeToString(s) + "." + base64.RawStdEncoding.EncodeToString(Key(password, s))
}
func CheckPassword(encoded, password string) bool {
	parts := strings.Split(encoded, ".")
	if len(parts) != 2 {
		return false
	}
	s, e := base64.RawStdEncoding.DecodeString(parts[0])
	if e != nil || len(s) != 16 {
		return false
	}
	h, e := base64.RawStdEncoding.DecodeString(parts[1])
	if e != nil {
		return false
	}
	return subtle.ConstantTimeCompare(h, Key(password, s)) == 1
}
func AEAD(key []byte) (cipher.AEAD, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}
func Seal(a cipher.AEAD, purpose string, b []byte) []byte {
	n := Random(a.NonceSize())
	return a.Seal(n, n, b, []byte(purpose))
}
func Unseal(a cipher.AEAD, purpose string, b []byte) ([]byte, error) {
	if len(b) < a.NonceSize() {
		return nil, errors.New("invalid encrypted record")
	}
	return a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], []byte(purpose))
}
