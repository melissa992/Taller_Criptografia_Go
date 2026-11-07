package crypto_test

import (
	"regexp"
	"testing"

	"github.com/melissa992/Taller_Criptografia_Go/internal/crypto"
)

var hex64Regex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestSHA256Hasher_KnownVectors(t *testing.T) {
	hasher := crypto.NewSHA256Hasher()

	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty string",
			input:    []byte(""),
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "standard 'abc' vector",
			input:    []byte("abc"),
			expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
		{
			name:     "longer sentence",
			input:    []byte("The quick brown fox jumps over the lazy dog"),
			expected: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasher.HashHex(tt.input)
			if got != tt.expected {
				t.Errorf("HashHex(%q) = %s, expected %s", string(tt.input), got, tt.expected)
			}
			if len(got) != 64 {
				t.Errorf("expected length 64, got %d", len(got))
			}
			if !hex64Regex.MatchString(got) {
				t.Errorf("hash %s does not match lowercase 64-character hex pattern", got)
			}
		})
	}
}
