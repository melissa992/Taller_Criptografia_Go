package service

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/melissa992/Taller_Criptografia_Go/internal/crypto"
	"github.com/melissa992/Taller_Criptografia_Go/internal/domain"
	"github.com/melissa992/Taller_Criptografia_Go/internal/logstore"
)

// VerificationService orchestrates artifact retrieval, decryption, recalculation, and integrity verification (steps 8–10).
type VerificationService interface {
	Verify() (domain.Report, error)
}

type verificationService struct {
	hasher    crypto.Hasher
	encryptor crypto.Encryptor
	store     logstore.ArtifactStore
}

// NewVerificationService constructs a VerificationService with injected dependencies.
func NewVerificationService(
	hasher crypto.Hasher,
	enc crypto.Encryptor,
	store logstore.ArtifactStore,
) VerificationService {
	return &verificationService{
		hasher:    hasher,
		encryptor: enc,
		store:     store,
	}
}

// Verify checks the stored digests and recovers the exact bytes of the original log.
func (s *verificationService) Verify() (domain.Report, error) {
	encrypted, err := s.store.Load(logstore.EncryptedLogFile)
	if err != nil {
		return domain.Report{}, fmt.Errorf("paso 8: leer %s: %w", logstore.EncryptedLogFile, err)
	}
	expectedEncryptedHash, err := s.loadHash(logstore.EncryptedHashFile)
	if err != nil {
		return domain.Report{}, fmt.Errorf("paso 8: %w", err)
	}
	encryptedHash := s.hasher.HashHex(encrypted)
	if subtle.ConstantTimeCompare([]byte(encryptedHash), []byte(expectedEncryptedHash)) != 1 {
		return domain.Report{}, fmt.Errorf("paso 8: el SHA-256 de %s no coincide con %s (esperado: %s, calculado: %s)",
			logstore.EncryptedLogFile, logstore.EncryptedHashFile, expectedEncryptedHash, encryptedHash)
	}

	key, err := s.store.Load(logstore.KeyFile)
	if err != nil {
		return domain.Report{}, fmt.Errorf("paso 8: leer %s: %w", logstore.KeyFile, err)
	}
	decrypted, err := s.encryptor.Decrypt(key, encrypted)
	if err != nil {
		return domain.Report{}, fmt.Errorf("paso 8: autenticar y descifrar %s: %w", logstore.EncryptedLogFile, err)
	}

	var log domain.Log
	if err := json.Unmarshal(decrypted, &log); err != nil {
		return domain.Report{}, fmt.Errorf("paso 8: reconstruir el log JSON: %w", err)
	}
	if log.LogID == "" || len(log.Events) == 0 || log.EventCount != len(log.Events) {
		return domain.Report{}, fmt.Errorf("paso 8: el log descifrado debe tener un identificador y un conteo válido de eventos")
	}

	plainHash, err := s.loadHash(logstore.LogHashFile)
	if err != nil {
		return domain.Report{}, fmt.Errorf("paso 9: %w", err)
	}
	decryptedHash := s.hasher.HashHex(decrypted)
	report := domain.Report{
		LogID:              log.LogID,
		EventCount:         len(log.Events),
		EventsByType:       make(map[domain.EventType]int),
		PlainLogHash:       plainHash,
		EncryptedLogHash:   encryptedHash,
		DecryptedLogHash:   decryptedHash,
		IntegrityPreserved: subtle.ConstantTimeCompare([]byte(plainHash), []byte(decryptedHash)) == 1,
	}
	for _, event := range log.Events {
		report.EventsByType[event.EventType]++
	}

	if !report.IntegrityPreserved {
		report.Details = "El SHA-256 del log descifrado difiere del SHA-256 original."
		return report, nil
	}
	if err := s.store.Save(logstore.DecryptedLogFile, decrypted, 0o600); err != nil {
		return domain.Report{}, fmt.Errorf("paso 9: guardar %s: %w", logstore.DecryptedLogFile, err)
	}
	report.Details = "El SHA-256 del log descifrado coincide con el SHA-256 original."
	return report, nil
}

func (s *verificationService) loadHash(name string) (string, error) {
	data, err := s.store.Load(name)
	if err != nil {
		return "", fmt.Errorf("leer %s: %w", name, err)
	}
	hash := strings.TrimSpace(string(data))
	if len(hash) != hex.EncodedLen(sha256.Size) {
		return "", fmt.Errorf("%s debe contener un SHA-256 de 64 caracteres hexadecimales", name)
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return "", fmt.Errorf("%s contiene un SHA-256 inválido: %w", name, err)
	}
	return strings.ToLower(hash), nil
}
