package keyfetcher

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type PublicKeyFetcher interface {
	FetchPublicKey() (*rsa.PublicKey, error)
}

type PrivateKeyFetcher interface {
	FetchPrivateKey() (*rsa.PrivateKey, error)
}

// From is a type definition for a function that returns a byte slice and an error.
type From func() ([]byte, error)

// FetchPublicKey parses the loaded key as an RSA public key.
func (f From) FetchPublicKey() (*rsa.PublicKey, error) {
	keyBytes, err := f()
	if err != nil {
		return nil, err
	}

	return jwt.ParseRSAPublicKeyFromPEM(keyBytes)
}

// FetchPrivateKey parses the loaded key as an RSA private key.
func (f From) FetchPrivateKey() (*rsa.PrivateKey, error) {
	keyBytes, err := f()
	if err != nil {
		return nil, err
	}

	return jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
}

// FromBase64Env receives an environment variable key as input,
// reads the Base64 encoded value from the specified environment variable, decodes it,
// and returns a From function.
func FromBase64Env(key string) From {
	return func() ([]byte, error) {
		keyBase64 := os.Getenv(key)
		if keyBase64 == "" {
			return nil, errors.New("key is not found")
		}

		return base64.StdEncoding.DecodeString(keyBase64)
	}
}
