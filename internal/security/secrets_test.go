package security

import (
	"encoding/base64"
	"os"
	"testing"
)

func TestSecretEncryptionRoundTrip(t *testing.T) {
	t.Setenv("OIDC_CONFIG_KEY", base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	cipher, e := Encrypt("example-client-secret")
	if e != nil {
		t.Fatal(e)
	}
	if string(cipher) == "example-client-secret" {
		t.Fatal("secret was not encrypted")
	}
	plain, e := Decrypt(cipher)
	if e != nil {
		t.Fatal(e)
	}
	if plain != "example-client-secret" {
		t.Fatalf("unexpected decrypted value %q", plain)
	}
}
func TestSecretKeyMustBe32Bytes(t *testing.T) {
	t.Setenv("OIDC_CONFIG_KEY", base64.RawStdEncoding.EncodeToString([]byte("short")))
	if _, e := Encrypt("secret"); e == nil {
		t.Fatal("accepted weak key")
	}
	_ = os.Getenv("OIDC_CONFIG_KEY")
}
