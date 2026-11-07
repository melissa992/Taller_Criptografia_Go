// Package logstore provides file persistence capabilities for storing and retrieving
// cryptographic artifacts and serialized logs on the filesystem.
package logstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// LogFile is the standard filename for the plaintext consolidated JSON log.
	LogFile = "log.json"

	// LogHashFile is the standard filename for the SHA-256 hash digest of the plaintext log.
	LogHashFile = "log.sha256"

	// EncryptedLogFile is the standard filename for the AES-256-GCM encrypted log artifact.
	EncryptedLogFile = "log.enc"

	// EncryptedHashFile is the standard filename for the SHA-256 hash digest of the encrypted log.
	EncryptedHashFile = "log.enc.sha256"

	// KeyFile is the standard filename for the raw 256-bit symmetric key.
	KeyFile = "key.bin"

	// DecryptedLogFile is the standard filename for the recovered plaintext log after decryption.
	DecryptedLogFile = "log.dec.json"
)

// ErrInvalidArtifactName indicates that the requested artifact name contains illegal path traversal characters.
var ErrInvalidArtifactName = errors.New("logstore: invalid artifact name, path traversal detected")

// ArtifactStore specifies persistence operations for reading and writing files.
type ArtifactStore interface {
	Save(name string, data []byte, perm os.FileMode) error
	Load(name string) ([]byte, error)
}

// FileStore implements ArtifactStore targeting a local filesystem directory.
type FileStore struct {
	baseDir string
}

// NewFileStore initializes a FileStore pointing to the given base directory.
func NewFileStore(baseDir string) *FileStore {
	return &FileStore{baseDir: baseDir}
}

// validateName guards against path traversal attacks by ensuring the name is a clean, single file element.
func (s *FileStore) validateName(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("%w: empty or invalid name %q", ErrInvalidArtifactName, name)
	}

	if strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
		return fmt.Errorf("%w: separator or traversal in %q", ErrInvalidArtifactName, name)
	}

	if filepath.Base(name) != name {
		return fmt.Errorf("%w: complex path in %q", ErrInvalidArtifactName, name)
	}

	return nil
}

// Save persists data to a file under the configured base directory with given permissions.
// If the base directory does not exist, it creates it automatically.
func (s *FileStore) Save(name string, data []byte, perm os.FileMode) error {
	if err := s.validateName(name); err != nil {
		return err
	}

	if err := os.MkdirAll(s.baseDir, 0o755); err != nil {
		return fmt.Errorf("logstore: failed to create base directory %q: %w", s.baseDir, err)
	}

	target := filepath.Join(s.baseDir, name)
	if err := os.WriteFile(target, data, perm); err != nil {
		return fmt.Errorf("logstore: failed to save artifact %q: %w", name, err)
	}

	return nil
}

// Load reads and returns the file bytes for the named artifact.
func (s *FileStore) Load(name string) ([]byte, error) {
	if err := s.validateName(name); err != nil {
		return nil, err
	}

	target := filepath.Join(s.baseDir, name)
	data, err := os.ReadFile(target)
	if err != nil {
		return nil, fmt.Errorf("logstore: failed to load artifact %q: %w", name, err)
	}

	return data, nil
}
