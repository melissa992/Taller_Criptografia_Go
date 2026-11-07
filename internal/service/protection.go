// Package service implements application orchestration and business workflows,
// depending strictly on abstractions (interfaces) rather than concrete implementations.
package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/melissa992/Taller_Criptografia_Go/internal/crypto"
	"github.com/melissa992/Taller_Criptografia_Go/internal/domain"
	"github.com/melissa992/Taller_Criptografia_Go/internal/logstore"
)

var (
	// ErrNoEvents indicates that the event slice provided for protection is empty.
	ErrNoEvents = errors.New("protection service: no events provided to protect")

	// ErrMissingIDGenerator indicates that the required UUID generator was not configured.
	ErrMissingIDGenerator = errors.New("protection service: ID generator function (WithIDFunc) is not configured")
)

// ProtectionResult holds summary data and cryptographic hashes produced during the protection workflow.
type ProtectionResult struct {
	LogID            string                   `json:"log_id"`
	EventCount       int                      `json:"event_count"`
	EventsByType     map[domain.EventType]int `json:"events_by_type"`
	PlainLogHash     string                   `json:"plain_log_hash"`
	EncryptedLogHash string                   `json:"encrypted_log_hash"`
	ArtifactFiles    []string                 `json:"artifact_files"`
}

// ProtectionService orchestrates the consolidation, hashing, and encryption of structured logs (steps 4–7).
type ProtectionService interface {
	Protect(events []domain.Event) (ProtectionResult, error)
}

// ProtectionOption allows functional configuration of the ProtectionService.
type ProtectionOption func(*protectionService)

// WithClock injects a custom time function for reproducible timestamps.
func WithClock(clock func() time.Time) ProtectionOption {
	return func(s *protectionService) {
		s.now = clock
	}
}

// WithIDFunc injects a custom unique ID generator (e.g. UUID v4).
func WithIDFunc(idFunc func() (string, error)) ProtectionOption {
	return func(s *protectionService) {
		s.newID = idFunc
	}
}

type protectionService struct {
	hasher    crypto.Hasher
	encryptor crypto.Encryptor
	store     logstore.ArtifactStore
	now       func() time.Time
	newID     func() (string, error)
}

// NewProtectionService constructs a ProtectionService with injected abstract dependencies.
func NewProtectionService(
	hasher crypto.Hasher,
	enc crypto.Encryptor,
	store logstore.ArtifactStore,
	opts ...ProtectionOption,
) ProtectionService {
	svc := &protectionService{
		hasher:    hasher,
		encryptor: enc,
		store:     store,
		now:       time.Now,
	}

	for _, opt := range opts {
		opt(svc)
	}

	return svc
}

// Protect executes steps 4 to 7 of the cryptography workshop pipeline:
// - Step 4: Consolidates domain.Log and saves log.json.
// - Step 5: Computes SHA-256 hash of log.json and saves log.sha256.
// - Step 6: Generates 256-bit key (key.bin, 0600), encrypts with AES-256-GCM, and saves log.enc.
// - Step 7: Computes SHA-256 hash of log.enc and saves log.enc.sha256.
func (s *protectionService) Protect(events []domain.Event) (ProtectionResult, error) {
	if len(events) == 0 {
		return ProtectionResult{}, ErrNoEvents
	}

	if s.newID == nil {
		return ProtectionResult{}, ErrMissingIDGenerator
	}

	// -------------------------------------------------------------------------
	// Paso 4: Consolidar eventos en un log JSON
	// -------------------------------------------------------------------------
	logID, err := s.newID()
	if err != nil {
		return ProtectionResult{}, fmt.Errorf("paso 4: generar log_id: %w", err)
	}

	logStructure := domain.Log{
		LogID:       logID,
		Version:     "1.0",
		GeneratedAt: s.now().UTC().Format(time.RFC3339),
		EventCount:  len(events),
		Events:      events,
	}

	// Serializar exactamente UNA vez; estos bytes exactos son la entrada para disco, hash y cifrado.
	bytesLog, err := json.MarshalIndent(logStructure, "", "  ")
	if err != nil {
		return ProtectionResult{}, fmt.Errorf("paso 4: serializar log: %w", err)
	}

	if err := s.store.Save(logstore.LogFile, bytesLog, 0o644); err != nil {
		return ProtectionResult{}, fmt.Errorf("paso 4: guardar %s: %w", logstore.LogFile, err)
	}

	// -------------------------------------------------------------------------
	// Paso 5: Hash del log completo en claro
	// -------------------------------------------------------------------------
	plainLogHash := s.hasher.HashHex(bytesLog)
	hashFileContent := []byte(plainLogHash + "\n")
	if err := s.store.Save(logstore.LogHashFile, hashFileContent, 0o644); err != nil {
		return ProtectionResult{}, fmt.Errorf("paso 5: guardar %s: %w", logstore.LogHashFile, err)
	}

	// -------------------------------------------------------------------------
	// Paso 6: Cifrar el log (artefacto separado + insumos criptográficos)
	// -------------------------------------------------------------------------
	key, err := s.encryptor.GenerateKey()
	if err != nil {
		return ProtectionResult{}, fmt.Errorf("paso 6: generar clave: %w", err)
	}

	// Guardar clave en reposo con permisos 0600 (lectura/escritura exclusiva usuario)
	if err := s.store.Save(logstore.KeyFile, key, 0o600); err != nil {
		return ProtectionResult{}, fmt.Errorf("paso 6: guardar %s: %w", logstore.KeyFile, err)
	}

	ciphertext, err := s.encryptor.Encrypt(key, bytesLog)
	if err != nil {
		return ProtectionResult{}, fmt.Errorf("paso 6: cifrar log: %w", err)
	}

	if err := s.store.Save(logstore.EncryptedLogFile, ciphertext, 0o644); err != nil {
		return ProtectionResult{}, fmt.Errorf("paso 6: guardar %s: %w", logstore.EncryptedLogFile, err)
	}

	// -------------------------------------------------------------------------
	// Paso 7: Hash del log cifrado
	// -------------------------------------------------------------------------
	encryptedLogHash := s.hasher.HashHex(ciphertext)
	encHashFileContent := []byte(encryptedLogHash + "\n")
	if err := s.store.Save(logstore.EncryptedHashFile, encHashFileContent, 0o644); err != nil {
		return ProtectionResult{}, fmt.Errorf("paso 7: guardar %s: %w", logstore.EncryptedHashFile, err)
	}

	// Contabilizar tipos de evento
	eventsByType := make(map[domain.EventType]int)
	for _, e := range events {
		eventsByType[e.EventType]++
	}

	return ProtectionResult{
		LogID:            logID,
		EventCount:       len(events),
		EventsByType:     eventsByType,
		PlainLogHash:     plainLogHash,
		EncryptedLogHash: encryptedLogHash,
		ArtifactFiles: []string{
			logstore.LogFile,
			logstore.LogHashFile,
			logstore.KeyFile,
			logstore.EncryptedLogFile,
			logstore.EncryptedHashFile,
		},
	}, nil
}
