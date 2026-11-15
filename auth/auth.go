// Package auth binds an HTTP authentication proof to the current TLS session.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// TLS exporter parameters and credential limits are shared by both transports.
const (
	ExporterLabel = "EXPORTER-quri-auth"
	BindingSize   = 32
	MinTokenSize  = 32
	MaxTokenSize  = 256
	MaxUsers      = 64
)

type credential struct {
	principal string
	token     string
}

// Authenticator owns an immutable snapshot of the server's credentials.
type Authenticator struct{ users []credential }

// New rejects empty identities, weak credentials and ambiguous shared tokens.
func New(tokens map[string]string) (*Authenticator, error) {
	if len(tokens) == 0 || len(tokens) > MaxUsers {
		return nil, errors.New("invalid number of authentication credentials")
	}
	a := &Authenticator{users: make([]credential, 0, len(tokens))}
	seen := make(map[string]struct{}, len(tokens))
	for principal, token := range tokens {
		if principal == "" || len(token) < MinTokenSize || len(token) > MaxTokenSize {
			return nil, errors.New("invalid authentication credential")
		}
		if _, exists := seen[token]; exists {
			return nil, errors.New("authentication credentials must be unique")
		}
		seen[token] = struct{}{}
		a.users = append(a.users, credential{principal: principal, token: token})
	}
	return a, nil
}

// Binding obtains key material only from an established TLS connection.
func Binding(export func(string, []byte, int) ([]byte, error)) ([]byte, error) {
	if export == nil {
		return nil, errors.New("missing TLS exporter")
	}
	return export(ExporterLabel, nil, BindingSize)
}

// Proof returns the URL-safe HMAC proof, never the static token itself.
func Proof(token string, binding []byte) (string, error) {
	if len(token) < MinTokenSize || len(token) > MaxTokenSize || len(binding) != BindingSize {
		return "", errors.New("invalid authentication input")
	}
	mac := hmac.New(sha256.New, []byte(token))
	if _, err := mac.Write(binding); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Verify accepts a proof only for this connection's exporter binding.
// Repeating it on the same connection is harmless and does not create a session.
func (a *Authenticator) Verify(proof string, binding []byte) (string, bool) {
	if len(binding) != BindingSize || len(proof) != base64.RawURLEncoding.EncodedLen(sha256.Size) {
		return "", false
	}
	var received [sha256.Size]byte
	if n, err := base64.RawURLEncoding.Decode(received[:], []byte(proof)); err != nil || n != len(received) {
		return "", false
	}
	var principal string
	for _, user := range a.users {
		mac := hmac.New(sha256.New, []byte(user.token))
		if _, err := mac.Write(binding); err != nil {
			return "", false
		}
		if hmac.Equal(received[:], mac.Sum(nil)) {
			principal = user.principal
		}
	}
	return principal, principal != ""
}
