package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

const testPrincipal = "alice"

func TestProofIsConnectionBound(t *testing.T) {
	token := strings.Repeat("a", MinTokenSize)
	tokens := map[string]string{testPrincipal: token}
	a, err := New(tokens)
	if err != nil {
		t.Fatal(err)
	}
	tokens[testPrincipal] = strings.Repeat("b", MinTokenSize)
	first := bytes.Repeat([]byte{1}, BindingSize)
	second := bytes.Repeat([]byte{2}, BindingSize)
	proof, err := Proof(token, first)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if principal, ok := a.Verify(proof, first); !ok || principal != testPrincipal {
			t.Fatalf("Verify on original connection = %q, %v, want alice, true", principal, ok)
		}
	}
	if principal, ok := a.Verify(proof, second); ok || principal != "" {
		t.Fatalf("replayed proof = %q, %v, want rejection", principal, ok)
	}
	for _, bad := range []string{"", token, "not-base64", strings.Repeat("x", len(proof))} {
		if _, ok := a.Verify(bad, first); ok {
			t.Errorf("Verify(%q) accepted an invalid proof", bad)
		}
	}
	mac := hmac.New(sha256.New, []byte(token))
	if _, err := mac.Write(first); err != nil {
		t.Fatal(err)
	}
	if want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)); proof != want {
		t.Fatalf("Proof = %q, want independent HMAC %q", proof, want)
	}
}

func TestCredentialsValidation(t *testing.T) {
	for _, tokens := range []map[string]string{nil, {"": "x"}, {testPrincipal: "short"}, {testPrincipal: strings.Repeat("x", 32), "bob": strings.Repeat("x", 32)}} {
		if _, err := New(tokens); err == nil {
			t.Errorf("New accepted invalid credentials")
		}
	}
	if _, err := Proof(strings.Repeat("x", 32), nil); err == nil {
		t.Error("Proof accepted missing TLS binding")
	}
}
