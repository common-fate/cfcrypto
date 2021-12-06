package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

// HashECDSAPublicKey returns the base64 encoded SHA256 hash of an ECDSA public key
func HashECDSAPublicKey(key *ecdsa.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}

	hasher := sha256.New()
	_, err = hasher.Write(pubBytes)
	if err != nil {
		return "", err
	}
	sha := hasher.Sum(nil)

	hashed := base64.StdEncoding.EncodeToString(sha)
	return hashed, nil
}

// ParseECDSAPublicKey parses and casts an ECDSA public key into a Go struct.
// The key must be encoded using PKIX, ASN.1 DER form (i.e. via `x509.MarshalPKIXPublicKey()`)
func ParseECDSAPublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, err
	}

	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("could not cast to ECDSA public key")
	}
	return key, nil
}

// MarshalECDSAPublicKey marshals an ECDSA public key into bytes
func MarshalECDSAPublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key)
}
