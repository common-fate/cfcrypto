package crypto

import "context"

// Encryptor performs symmetric encryption on provided text.
// Used to encrypt simple plaintext strings such as session tokens to
// be sent to users.
// Encryptor is not aware of key rotation - this will need to be
// handled outside of the Encrypt and Decrypt methods.
type Encryptor interface {
	Encrypt(ctx context.Context, plaintext string) (string, error)
	Decrypt(ctx context.Context, ciphertext string) (string, error)
}

// NoOpEncryptor is for *testing only*
type NoOpEncryptor struct{}

func (e *NoOpEncryptor) Encrypt(ctx context.Context, plaintext string) (string, error) {
	return plaintext, nil
}

func (e *NoOpEncryptor) Decrypt(ctx context.Context, ciphertext string) (string, error) {
	return ciphertext, nil
}
