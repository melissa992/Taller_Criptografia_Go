package crypto_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/melissa992/Taller_Criptografia_Go/internal/crypto"
)

func TestAESGCMEncryptor_GenerateKey(t *testing.T) {
	enc := crypto.NewAESGCMEncryptor()

	k1, err := enc.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}

	if len(k1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(k1))
	}

	k2, err := enc.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey returned error on second call: %v", err)
	}

	if bytes.Equal(k1, k2) {
		t.Fatal("two consecutive generated keys are unexpectedly identical")
	}
}

func TestAESGCMEncryptor_Roundtrip(t *testing.T) {
	enc := crypto.NewAESGCMEncryptor()
	key, err := enc.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{name: "empty slice", plaintext: []byte{}},
		{name: "short string", plaintext: []byte("sensitive academic record")},
		{name: "1 MiB data", plaintext: bytes.Repeat([]byte("A"), 1024*1024)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := enc.Encrypt(key, tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Format check: minimum length is 12 (nonce) + len(plaintext) + 16 (tag)
			expectedLen := 12 + len(tt.plaintext) + 16
			if len(ciphertext) != expectedLen {
				t.Fatalf("expected ciphertext length %d, got %d", expectedLen, len(ciphertext))
			}

			decrypted, err := enc.Decrypt(key, ciphertext)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Fatalf("decrypted plaintext does not match original")
			}
		})
	}
}

func TestAESGCMEncryptor_NonceUniqueness(t *testing.T) {
	enc := crypto.NewAESGCMEncryptor()
	key, err := enc.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	plaintext := []byte("identical payload to encrypt twice")

	c1, err1 := enc.Encrypt(key, plaintext)
	c2, err2 := enc.Encrypt(key, plaintext)
	if err1 != nil || err2 != nil {
		t.Fatalf("encryption failed: %v, %v", err1, err2)
	}

	if bytes.Equal(c1, c2) {
		t.Fatal("two encryptions of the same plaintext produced identical ciphertext (nonce reuse)")
	}

	// Nonce is first 12 bytes
	nonce1 := c1[:12]
	nonce2 := c2[:12]
	if bytes.Equal(nonce1, nonce2) {
		t.Fatal("two encryptions reused the same 12-byte nonce")
	}
}

func TestAESGCMEncryptor_TamperDetection(t *testing.T) {
	enc := crypto.NewAESGCMEncryptor()
	key, err := enc.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	plaintext := []byte("vital grades data that must be integrity-protected")
	ciphertext, err := enc.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Tamper in nonce (indices 0..11)
	t.Run("tamper nonce", func(t *testing.T) {
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		tampered[3] ^= 0xFF

		_, err := enc.Decrypt(key, tampered)
		if err == nil {
			t.Fatal("expected decryption error on tampered nonce, got nil")
		}
		if !errors.Is(err, crypto.ErrAuthenticationFailed) {
			t.Fatalf("expected ErrAuthenticationFailed, got %v", err)
		}
	})

	// Tamper in ciphertext body (indices 12..len-17)
	t.Run("tamper ciphertext body", func(t *testing.T) {
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		tampered[15] ^= 0x01

		_, err := enc.Decrypt(key, tampered)
		if err == nil {
			t.Fatal("expected decryption error on tampered ciphertext, got nil")
		}
		if !errors.Is(err, crypto.ErrAuthenticationFailed) {
			t.Fatalf("expected ErrAuthenticationFailed, got %v", err)
		}
	})

	// Tamper in authentication tag (last 16 bytes)
	t.Run("tamper tag", func(t *testing.T) {
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		tampered[len(tampered)-1] ^= 0x55

		_, err := enc.Decrypt(key, tampered)
		if err == nil {
			t.Fatal("expected decryption error on tampered tag, got nil")
		}
		if !errors.Is(err, crypto.ErrAuthenticationFailed) {
			t.Fatalf("expected ErrAuthenticationFailed, got %v", err)
		}
	})

	// Wrong key
	t.Run("wrong key", func(t *testing.T) {
		wrongKey, _ := enc.GenerateKey()
		_, err := enc.Decrypt(wrongKey, ciphertext)
		if err == nil {
			t.Fatal("expected decryption error with wrong key, got nil")
		}
		if !errors.Is(err, crypto.ErrAuthenticationFailed) {
			t.Fatalf("expected ErrAuthenticationFailed, got %v", err)
		}
	})
}

func TestAESGCMEncryptor_InvalidInputs(t *testing.T) {
	enc := crypto.NewAESGCMEncryptor()
	validKey, _ := enc.GenerateKey()

	t.Run("invalid key size Encrypt", func(t *testing.T) {
		_, err := enc.Encrypt([]byte("short-key"), []byte("data"))
		if !errors.Is(err, crypto.ErrInvalidKeySize) {
			t.Fatalf("expected ErrInvalidKeySize, got %v", err)
		}
	})

	t.Run("invalid key size Decrypt", func(t *testing.T) {
		_, err := enc.Decrypt(make([]byte, 16), []byte("any-data-at-least-28-bytes-long-here"))
		if !errors.Is(err, crypto.ErrInvalidKeySize) {
			t.Fatalf("expected ErrInvalidKeySize, got %v", err)
		}
	})

	t.Run("ciphertext too short Decrypt", func(t *testing.T) {
		_, err := enc.Decrypt(validKey, []byte("short"))
		if !errors.Is(err, crypto.ErrCiphertextTooShort) {
			t.Fatalf("expected ErrCiphertextTooShort, got %v", err)
		}
	})
}

func TestAESGCMEncryptor_Confidentiality_NoPlaintextLeak(t *testing.T) {
	enc := crypto.NewAESGCMEncryptor()
	key, _ := enc.GenerateKey()

	sensitiveWord := []byte("TOP_SECRET_GRADE_MODIFIED_STUDENT_12345")
	ciphertext, err := enc.Encrypt(key, sensitiveWord)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if bytes.Contains(ciphertext, sensitiveWord) {
		t.Fatal("ciphertext contains plain text leak")
	}
}
