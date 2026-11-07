// Package service implements application orchestration and business workflows,
// depending strictly on abstractions (interfaces) rather than concrete implementations.
package service

import (
	"errors"

	"github.com/melissa992/Taller_Criptografia_Go/internal/crypto"
	"github.com/melissa992/Taller_Criptografia_Go/internal/domain"
	"github.com/melissa992/Taller_Criptografia_Go/internal/generator"
	"github.com/melissa992/Taller_Criptografia_Go/internal/logstore"
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

// ProtectionService orchestrates the creation, hashing, and encryption of structured logs (steps 1–7).
type ProtectionService interface {
	Protect(n int) (ProtectionResult, error)
}

type protectionService struct {
	generator generator.EventGenerator
	hasher    crypto.Hasher
	encryptor crypto.Encryptor
	store     logstore.ArtifactStore
}

// NewProtectionService constructs a ProtectionService with injected dependencies.
func NewProtectionService(
	gen generator.EventGenerator,
	hasher crypto.Hasher,
	enc crypto.Encryptor,
	store logstore.ArtifactStore,
) ProtectionService {
	return &protectionService{
		generator: gen,
		hasher:    hasher,
		encryptor: enc,
		store:     store,
	}
}

// Protect executes the pipeline: generates n events, calculates hashes, serializes the log,
// saves plain log & hash, encrypts the log, and saves the ciphertext & its hash.
func (s *protectionService) Protect(n int) (ProtectionResult, error) {
	return ProtectionResult{}, errors.New("not implemented")
}
