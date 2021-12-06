package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseECDSAPublicKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pub := priv.PublicKey

	bytes, err := x509.MarshalPKIXPublicKey(&pub)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseECDSAPublicKey(bytes)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, pub, *parsed)

}
