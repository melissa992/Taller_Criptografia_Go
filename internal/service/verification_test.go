package service_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melissa992/Taller_Criptografia_Go/internal/crypto"
	"github.com/melissa992/Taller_Criptografia_Go/internal/domain"
	"github.com/melissa992/Taller_Criptografia_Go/internal/logstore"
	"github.com/melissa992/Taller_Criptografia_Go/internal/service"
)

func TestVerificationService_RecoversWithoutOriginalFile(t *testing.T) {
	dir := t.TempDir()
	store := logstore.NewFileStore(dir)
	hasher := crypto.NewSHA256Hasher()
	encryptor := crypto.NewAESGCMEncryptor()
	protection := service.NewProtectionService(hasher, encryptor, store, service.WithIDFunc(func() (string, error) {
		return "log-auditoria", nil
	}))
	protected, err := protection.Protect(sampleEvents())
	if err != nil {
		t.Fatal(err)
	}
	original, err := store.Load(logstore.LogFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, logstore.LogFile)); err != nil {
		t.Fatal(err)
	}

	verification := service.NewVerificationService(hasher, encryptor, logstore.NewFileStore(dir))
	report, err := verification.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !report.IntegrityPreserved || report.LogID != protected.LogID ||
		report.PlainLogHash != protected.PlainLogHash || report.DecryptedLogHash != protected.PlainLogHash ||
		report.EncryptedLogHash != protected.EncryptedLogHash {
		t.Fatalf("reporte incorrecto: %+v", report)
	}
	if report.EventCount != 2 || report.EventsByType[domain.GradeRegistered] != 1 ||
		report.EventsByType[domain.GradeModified] != 1 {
		t.Fatalf("conteo incorrecto: %+v", report)
	}
	decrypted, err := store.Load(logstore.DecryptedLogFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, decrypted) {
		t.Fatal("el archivo recuperado no conserva los bytes originales")
	}
}

func TestVerificationService_RejectsAlteredArtifacts(t *testing.T) {
	hasher := crypto.NewSHA256Hasher()
	encryptor := crypto.NewAESGCMEncryptor()
	for _, tc := range []struct {
		name      string
		change    func(*fakeStore)
		wantErr   string
		wantErrIs error
	}{
		{
			name: "hash original diferente",
			change: func(store *fakeStore) {
				store.files[logstore.LogHashFile] = []byte(hasher.HashHex([]byte("otro log")) + "\r\n")
			},
		},
		{
			name: "hash original inválido",
			change: func(store *fakeStore) {
				store.files[logstore.LogHashFile] = []byte(strings.Repeat("x", 64))
			},
			wantErr: logstore.LogHashFile,
		},
		{
			name: "cifrado alterado",
			change: func(store *fakeStore) {
				store.files[logstore.EncryptedLogFile][0] ^= 1
			},
			wantErr: "no coincide",
		},
		{
			name: "cifrado alterado con hash actualizado",
			change: func(store *fakeStore) {
				encrypted := store.files[logstore.EncryptedLogFile]
				encrypted[len(encrypted)-1] ^= 1
				store.files[logstore.EncryptedHashFile] = []byte(hasher.HashHex(encrypted))
			},
			wantErr:   "autenticar y descifrar",
			wantErrIs: crypto.ErrAuthenticationFailed,
		},
		{
			name: "clave ausente",
			change: func(store *fakeStore) {
				delete(store.files, logstore.KeyFile)
			},
			wantErr:   logstore.KeyFile,
			wantErrIs: os.ErrNotExist,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore()
			protection := service.NewProtectionService(hasher, encryptor, store, service.WithIDFunc(func() (string, error) {
				return "log-auditoria", nil
			}))
			if _, err := protection.Protect(sampleEvents()); err != nil {
				t.Fatal(err)
			}
			tc.change(store)

			report, err := service.NewVerificationService(hasher, encryptor, store).Verify()
			if tc.wantErr == "" {
				if err != nil || report.IntegrityPreserved || report.DecryptedLogHash == "" ||
					report.PlainLogHash == report.DecryptedLogHash {
					t.Fatalf("se esperaba una comparación negativa, reporte: %+v, error: %v", report, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) ||
				(tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs)) {
				t.Fatalf("se esperaba error %q, se obtuvo %v", tc.wantErr, err)
			}
			if _, err := store.Load(logstore.DecryptedLogFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("el descifrado fallido publicó un archivo, error de lectura: %v", err)
			}
		})
	}
}
