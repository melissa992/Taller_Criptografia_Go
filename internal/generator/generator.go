// Package generator provides simulated generation of academic grade events
// for testing and demonstration purposes.
package generator

import (
	"errors"

	"github.com/melissa992/Taller_Criptografia_Go/internal/domain"
)

// EventGenerator defines the contract for producing synthetic academic events.
type EventGenerator interface {
	Generate(n int) ([]domain.Event, error)
}

// RandomEventGenerator generates synthetic grade registration and modification events
// using pseudo-random data generators for non-cryptographic attributes.
type RandomEventGenerator struct{}

// NewRandomEventGenerator creates an uninitialized RandomEventGenerator stub.
func NewRandomEventGenerator() *RandomEventGenerator {
	return &RandomEventGenerator{}
}

// Generate creates n simulated events.
func (g *RandomEventGenerator) Generate(n int) ([]domain.Event, error) {
	return nil, errors.New("not implemented")
}

