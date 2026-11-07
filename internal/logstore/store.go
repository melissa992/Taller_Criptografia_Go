// Package logstore provides file persistence capabilities for storing and retrieving
// cryptographic artifacts and serialized logs on the filesystem.
package logstore

import (
	"errors"
	"os"
)

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

// Save persists data to a file under the configured base directory with given permissions.
func (s *FileStore) Save(name string, data []byte, perm os.FileMode) error {
	return errors.New("not implemented")
}

// Load reads and returns the file bytes for the named artifact.
func (s *FileStore) Load(name string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

