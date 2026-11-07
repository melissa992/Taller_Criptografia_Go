package logstore_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/melissa992/Taller_Criptografia_Go/internal/logstore"
)

func TestFileStore_SaveAndLoad_Roundtrip(t *testing.T) {
	tempDir := filepath.Join(t.TempDir(), "nested", "subfolder")
	store := logstore.NewFileStore(tempDir)

	content := []byte("payload content for artifact testing")
	err := store.Save(logstore.LogFile, content, 0o644)
	if err != nil {
		t.Fatalf("Save returned unexpected error: %v", err)
	}

	loaded, err := store.Load(logstore.LogFile)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}

	if !bytes.Equal(loaded, content) {
		t.Fatalf("loaded bytes %q do not match saved bytes %q", string(loaded), string(content))
	}
}

func TestFileStore_PathTraversalRejection(t *testing.T) {
	tempDir := t.TempDir()
	store := logstore.NewFileStore(tempDir)

	traversalNames := []string{
		"../escape.txt",
		"..\\escape.txt",
		"sub/folder.txt",
		"sub\\folder.txt",
		"..",
		".",
		"/root.txt",
		"\\root.txt",
	}

	for _, name := range traversalNames {
		t.Run("Save: "+name, func(t *testing.T) {
			err := store.Save(name, []byte("data"), 0o644)
			if !errors.Is(err, logstore.ErrInvalidArtifactName) {
				t.Errorf("expected ErrInvalidArtifactName for Save(%q), got %v", name, err)
			}
		})

		t.Run("Load: "+name, func(t *testing.T) {
			_, err := store.Load(name)
			if !errors.Is(err, logstore.ErrInvalidArtifactName) {
				t.Errorf("expected ErrInvalidArtifactName for Load(%q), got %v", name, err)
			}
		})
	}
}

func TestFileStore_LoadNonExistent(t *testing.T) {
	tempDir := t.TempDir()
	store := logstore.NewFileStore(tempDir)

	_, err := store.Load("missing_file.json")
	if err == nil {
		t.Fatal("expected error loading non-existent file, got nil")
	}
}
