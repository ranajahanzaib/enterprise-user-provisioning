package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
)

func key() ([]byte, error) {
	v := os.Getenv("OIDC_CONFIG_KEY")
	b, e := base64.RawStdEncoding.DecodeString(v)
	if e != nil || len(b) != 32 {
		return nil, errors.New("OIDC_CONFIG_KEY must be base64 for exactly 32 random bytes")
	}
	return b, nil
}
func ValidateKey() error { _, e := key(); return e }
func Encrypt(plain string) ([]byte, error) {
	k, e := key()
	if e != nil {
		return nil, e
	}
	a, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(a)
	if e != nil {
		return nil, e
	}
	n := make([]byte, g.NonceSize())
	if _, e = io.ReadFull(rand.Reader, n); e != nil {
		return nil, e
	}
	return g.Seal(n, n, []byte(plain), nil), nil
}
func Decrypt(value []byte) (string, error) {
	k, e := key()
	if e != nil {
		return "", e
	}
	a, e := aes.NewCipher(k)
	if e != nil {
		return "", e
	}
	g, e := cipher.NewGCM(a)
	if e != nil {
		return "", e
	}
	if len(value) < g.NonceSize() {
		return "", errors.New("invalid encrypted OIDC secret")
	}
	plain, e := g.Open(nil, value[:g.NonceSize()], value[g.NonceSize():], nil)
	return string(plain), e
}
