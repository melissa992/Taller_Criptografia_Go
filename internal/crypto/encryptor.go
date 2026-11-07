package crypto

import "errors"

// Encryptor defines the contract for key generation, symmetric encryption, and decryption.
type Encryptor interface {
	GenerateKey() ([]byte, error)
	Encrypt(key, plaintext []byte) ([]byte, error) // Returns nonce || ciphertext || tag
	Decrypt(key, data []byte) ([]byte, error)
}

// AESGCMEncryptor implements AES-256-GCM authenticated encryption.
type AESGCMEncryptor struct{}

// NewAESGCMEncryptor constructs an AESGCMEncryptor instance.
func NewAESGCMEncryptor() *AESGCMEncryptor {
	return &AESGCMEncryptor{}
}

// GenerateKey produces a cryptographically secure 256-bit (32-byte) symmetric key.
func (e *AESGCMEncryptor) GenerateKey() ([]byte, error) {
	return nil, errors.New("not implemented")
}

// Encrypt encrypts plaintext using AES-256-GCM with a fresh 12-byte nonce prefixed to the output.
func (e *AESGCMEncryptor) Encrypt(key, plaintext []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

// Decrypt authenticates and decrypts data (expected layout: nonce || ciphertext || tag) using key.
func (e *AESGCMEncryptor) Decrypt(key, data []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

