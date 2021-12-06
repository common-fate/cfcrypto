package crypto

import "crypto/sha256"

// Hash calculates the SHA256 hash of a string
func Hash(s string) ([]byte, error) {
	hasher := sha256.New()
	_, err := hasher.Write([]byte(s))
	if err != nil {
		return nil, err
	}
	hash := hasher.Sum(nil)
	return hash, nil
}
