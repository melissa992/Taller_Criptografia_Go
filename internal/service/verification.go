package service

import (
	"errors"

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

// Verify loads the encrypted log and key, decrypts the content, compares plain and decrypted hashes,
// and produces a complete integrity report.
func (s *verificationService) Verify() (domain.Report, error) {
	return domain.Report{}, errors.New("not implemented")
}

