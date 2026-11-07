package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrInvalidKeySize indicates that the provided key does not meet the 32-byte requirement for AES-256.
	ErrInvalidKeySize = errors.New("crypto: invalid key size, AES-256 requires 32 bytes")

	// ErrCiphertextTooShort indicates that data length is smaller than nonce plus authentication tag.
	ErrCiphertextTooShort = errors.New("crypto: ciphertext too short to contain valid nonce and tag")

	// ErrAuthenticationFailed indicates that the ciphertext could not be authenticated during decryption.
	ErrAuthenticationFailed = errors.New("crypto: authentication failed, ciphertext is invalid or tampered")
)

// Encryptor defines the contract for key generation, symmetric encryption, and decryption.
type Encryptor interface {
	GenerateKey() ([]byte, error)
	Encrypt(key, plaintext []byte) ([]byte, error) // Returns nonce || ciphertext || tag
	Decrypt(key, data []byte) ([]byte, error)
}

// AESGCMEncryptor implements AES-256-GCM authenticated encryption.
//
// Architectural Rationale:
// 1. AES-GCM vs CBC / ECB:
//   - AES-GCM is an Authenticated Encryption with Associated Data (AEAD) cipher. It guarantees both
//     confidentiality and ciphertext integrity/authenticity using a Galois Message Authentication Code (GMAC).
//   - AES-CBC requires separate MAC calculation (Encrypt-then-MAC) and is vulnerable to padding oracle attacks.
//   - AES-ECB leaks identical plaintext block structures and is strictly insecure for structured data like JSON.
//
// 2. Nonce Uniqueness:
//   - In Galois/Counter Mode, reusing a nonce with the same key critically compromises security:
//     an adversary can recover the authentication subkey (GHASH) and forge messages, as well as
//     reveal the XOR difference of plaintexts.
//   - Every call to Encrypt generates a fresh 12-byte (96-bit) cryptographically secure random nonce.
type AESGCMEncryptor struct{}

// NewAESGCMEncryptor constructs an AESGCMEncryptor instance.
func NewAESGCMEncryptor() *AESGCMEncryptor {
	return &AESGCMEncryptor{}
}

// GenerateKey produces a cryptographically secure 256-bit (32-byte) symmetric key using crypto/rand.
func (e *AESGCMEncryptor) GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate 256-bit key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a fresh 12-byte nonce prefixed to the output.
// The output slice format is: nonce (12 bytes) || ciphertext || authentication_tag (16 bytes).
func (e *AESGCMEncryptor) Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to initialize GCM mode: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate cryptographic nonce: %w", err)
	}

	// gcm.Seal appends the ciphertext and the 16-byte tag to the nonce slice prefix.
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return sealed, nil
}

// Decrypt authenticates and decrypts data (expected layout: nonce (12 bytes) || ciphertext || tag (16 bytes)) using key.
// If verification fails, it wraps ErrAuthenticationFailed without leaking internal cryptographic specifics.
func (e *AESGCMEncryptor) Decrypt(key, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to initialize GCM mode: %w", err)
	}

	minLen := gcm.NonceSize() + gcm.Overhead()
	if len(data) < minLen {
		return nil, fmt.Errorf("%w: expected at least %d bytes, got %d", ErrCiphertextTooShort, minLen, len(data))
	}

	nonce := data[:gcm.NonceSize()]
	ciphertextAndTag := data[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertextAndTag, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAuthenticationFailed, err)
	}

	return plaintext, nil
}
