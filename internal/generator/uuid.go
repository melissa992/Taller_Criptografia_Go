package generator

import (
	"crypto/rand"
	"fmt"
)

// generateUUIDv4 generates an RFC 4122 compliant version 4 UUID using cryptographic randomness.
func generateUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("failed to generate random bytes for UUID v4: %w", err)
	}

	// Set version to 4 (bits 4-7 of time_hi_and_version to 0100)
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant to RFC 4122 (bits 6-7 of clock_seq_hi_and_reserved to 10)
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4],
		b[4:6],
		b[6:8],
		b[8:10],
		b[10:16],
	), nil
}

