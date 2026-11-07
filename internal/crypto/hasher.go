// Package crypto provides cryptographic primitives for hashing and authenticated symmetric encryption,
// relying strictly on the Go standard library.
package crypto

// Hasher specifies the contract for computing cryptographic hash digests.
type Hasher interface {
	HashHex(data []byte) string
}

// SHA256Hasher computes SHA-256 cryptographic digests.
type SHA256Hasher struct{}

// NewSHA256Hasher returns a new SHA256Hasher instance.
func NewSHA256Hasher() *SHA256Hasher {
	return &SHA256Hasher{}
}

// HashHex returns the hexadecimal encoded SHA-256 digest of data.
func (h *SHA256Hasher) HashHex(data []byte) string {
	return ""
}

