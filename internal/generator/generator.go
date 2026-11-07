// Package generator provides simulated generation of academic grade events
// for testing and demonstration purposes.
package generator

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/melissa992/Taller_Criptografia_Go/internal/domain"
)

const (
	// MaxEvents defines the maximum allowed event batch size.
	MaxEvents = 10000
)

// ErrInvalidEventCount is returned when the requested event count is outside [1, MaxEvents].
var ErrInvalidEventCount = errors.New("event count must be between 1 and 10000")

// EventGenerator defines the contract for producing synthetic academic events.
type EventGenerator interface {
	Generate(n int) ([]domain.Event, error)
}

// Option configures a RandomEventGenerator instance.
type Option func(*RandomEventGenerator)

// WithSeed configures a deterministic PCG seed for simulated data generation.
func WithSeed(seed1, seed2 uint64) Option {
	return func(g *RandomEventGenerator) {
		g.rng = rand.New(rand.NewPCG(seed1, seed2))
	}
}

// WithClock sets a custom clock function for timestamp generation.
func WithClock(clock func() time.Time) Option {
	return func(g *RandomEventGenerator) {
		g.now = clock
	}
}

// WithIDFunc sets a custom identifier generator function.
func WithIDFunc(idFunc func() (string, error)) Option {
	return func(g *RandomEventGenerator) {
		g.newID = idFunc
	}
}

// RandomEventGenerator generates synthetic grade registration and modification events
// using pseudo-random generators for non-cryptographic attributes and cryptographic entropy for IDs.
type RandomEventGenerator struct {
	rng   *rand.Rand
	now   func() time.Time
	newID func() (string, error)
}

// NewRandomEventGenerator creates an initialized RandomEventGenerator with default production settings
// or overridden functional options.
func NewRandomEventGenerator(opts ...Option) *RandomEventGenerator {
	var s1, s2 uint64
	var b [16]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		s1 = uint64(time.Now().UnixNano())
		s2 = 1
	} else {
		s1 = binary.LittleEndian.Uint64(b[0:8])
		s2 = binary.LittleEndian.Uint64(b[8:16])
	}

	gen := &RandomEventGenerator{
		rng:   rand.New(rand.NewPCG(s1, s2)),
		now:   time.Now,
		newID: generateUUIDv4,
	}

	for _, opt := range opts {
		opt(gen)
	}

	return gen
}

// Generate creates n simulated events respecting integrity, uniform grade distributions,
// and realistic pseudo-anonymized entity pools.
func (g *RandomEventGenerator) Generate(n int) ([]domain.Event, error) {
	if n < 1 || n > MaxEvents {
		return nil, fmt.Errorf("%w: received %d", ErrInvalidEventCount, n)
	}

	// Entity pools for realistic event repetition:
	// 5 professors, 20 students, and 5 courses.
	actors := make([]string, 5)
	for i := range actors {
		actors[i] = fmt.Sprintf("doc-%06x", g.rng.IntN(0x1000000))
	}

	students := make([]string, 20)
	for i := range students {
		students[i] = fmt.Sprintf("est-%06x", g.rng.IntN(0x1000000))
	}

	courses := make([]string, 5)
	for i := range courses {
		courses[i] = fmt.Sprintf("cur-%06x", g.rng.IntN(0x1000000))
	}

	events := make([]domain.Event, n)
	baseTime := g.now().UTC()

	for i := 0; i < n; i++ {
		id, err := g.newID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate event ID at index %d: %w", i, err)
		}

		actor := actors[g.rng.IntN(len(actors))]
		student := students[g.rng.IntN(len(students))]
		course := courses[g.rng.IntN(len(courses))]

		// Ensure non-decreasing timestamps across the batch.
		eventTimestamp := baseTime.Add(time.Duration(i) * time.Second).Format(time.RFC3339)

		event := domain.Event{
			EventID:    id,
			Timestamp:  eventTimestamp,
			ActorUID:   actor,
			StudentUID: student,
			CourseUID:  course,
		}

		// 50/50 probability distribution between GRADE_REGISTERED and GRADE_MODIFIED
		if g.rng.IntN(2) == 0 {
			event.EventType = domain.GradeRegistered

			// Uniform discrete distribution over {0.0, 0.1, ..., 5.0}:
			// Architectural rationale:
			// Rounding a continuous uniform float would yield half-width intervals for boundary
			// points (0.0 receives [0.0, 0.05), 5.0 receives [4.95, 5.0]), halving their probability.
			// Direct discrete sampling over 51 points gives each grade an identical 1/51 probability.
			grade := float64(g.rng.IntN(51)) / 10.0
			event.Grade = &grade
		} else {
			event.EventType = domain.GradeModified

			prevGrade := float64(g.rng.IntN(51)) / 10.0
			newGrade := prevGrade
			for newGrade == prevGrade {
				newGrade = float64(g.rng.IntN(51)) / 10.0
			}

			event.PreviousGrade = &prevGrade
			event.NewGrade = &newGrade
		}

		// Compute payload hash as the final step with the event fully populated.
		hash, err := domain.ComputePayloadHash(event)
		if err != nil {
			return nil, fmt.Errorf("failed to compute payload hash at index %d: %w", i, err)
		}
		event.PayloadHash = hash

		events[i] = event
	}

	return events, nil
}
