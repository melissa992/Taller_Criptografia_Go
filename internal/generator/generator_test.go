package generator_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"testing"
	"time"

	"github.com/melissa992/Taller_Criptografia_Go/internal/domain"
	"github.com/melissa992/Taller_Criptografia_Go/internal/generator"
)

var (
	actorUIDRegex   = regexp.MustCompile(`^doc-[0-9a-f]{6}$`)
	studentUIDRegex = regexp.MustCompile(`^est-[0-9a-f]{6}$`)
	courseUIDRegex  = regexp.MustCompile(`^cur-[0-9a-f]{6}$`)
)

func TestRandomEventGenerator_InvalidCounts(t *testing.T) {
	gen := generator.NewRandomEventGenerator()

	testCases := []int{0, -1, -50, generator.MaxEvents + 1, 20000}

	for _, n := range testCases {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			events, err := gen.Generate(n)
			if err == nil {
				t.Fatalf("expected error for n=%d, got nil", n)
			}
			if !errors.Is(err, generator.ErrInvalidEventCount) {
				t.Errorf("expected ErrInvalidEventCount, got %v", err)
			}
			if events != nil {
				t.Errorf("expected nil events, got slice of length %d", len(events))
			}
		})
	}
}

func TestRandomEventGenerator_Reproducibility(t *testing.T) {
	fixedTime := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixedTime }

	makeIDFunc := func() func() (string, error) {
		var idCounter int
		return func() (string, error) {
			idCounter++
			return fmt.Sprintf("00000000-0000-4000-8000-%012d", idCounter), nil
		}
	}

	g1 := generator.NewRandomEventGenerator(
		generator.WithSeed(42, 84),
		generator.WithClock(clock),
		generator.WithIDFunc(makeIDFunc()),
	)

	g2 := generator.NewRandomEventGenerator(
		generator.WithSeed(42, 84),
		generator.WithClock(clock),
		generator.WithIDFunc(makeIDFunc()),
	)

	events1, err1 := g1.Generate(50)
	events2, err2 := g2.Generate(50)

	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected generation errors: %v, %v", err1, err2)
	}

	if len(events1) != len(events2) {
		t.Fatalf("expected identical length, got %d and %d", len(events1), len(events2))
	}

	for i := range events1 {
		e1, e2 := events1[i], events2[i]
		if e1.EventID != e2.EventID ||
			e1.EventType != e2.EventType ||
			e1.Timestamp != e2.Timestamp ||
			e1.ActorUID != e2.ActorUID ||
			e1.StudentUID != e2.StudentUID ||
			e1.CourseUID != e2.CourseUID ||
			e1.PayloadHash != e2.PayloadHash {
			t.Fatalf("event at index %d differs between deterministic runs", i)
		}
	}
}

func TestRandomEventGenerator_BatchIntegrityAndProperties(t *testing.T) {
	gen := generator.NewRandomEventGenerator()
	const n = 5000

	events, err := gen.Generate(n)
	if err != nil {
		t.Fatalf("failed to generate %d events: %v", n, err)
	}

	if len(events) != n {
		t.Fatalf("expected %d events, got %d", n, len(events))
	}

	var registeredCount, modifiedCount int
	var previousTimestamp time.Time

	// Grade distribution tracker over 51 possible discrete bins (0 to 50 for 0.0 to 5.0)
	gradeBuckets := make(map[int]int)

	for i, e := range events {
		// Verify payload hash on every event
		valid, err := domain.VerifyPayloadHash(e)
		if err != nil {
			t.Fatalf("event %d: error verifying payload hash: %v", i, err)
		}
		if !valid {
			t.Fatalf("event %d: payload hash verification failed", i)
		}

		// Verify UID patterns
		if !actorUIDRegex.MatchString(e.ActorUID) {
			t.Errorf("event %d: invalid ActorUID format %s", i, e.ActorUID)
		}
		if !studentUIDRegex.MatchString(e.StudentUID) {
			t.Errorf("event %d: invalid StudentUID format %s", i, e.StudentUID)
		}
		if !courseUIDRegex.MatchString(e.CourseUID) {
			t.Errorf("event %d: invalid CourseUID format %s", i, e.CourseUID)
		}

		// Verify non-decreasing RFC3339 timestamps
		ts, err := time.Parse(time.RFC3339, e.Timestamp)
		if err != nil {
			t.Fatalf("event %d: invalid RFC3339 timestamp %s: %v", i, e.Timestamp, err)
		}
		if i > 0 && ts.Before(previousTimestamp) {
			t.Fatalf("event %d: timestamp %v is earlier than previous %v", i, ts, previousTimestamp)
		}
		previousTimestamp = ts

		// Verify event type invariants
		switch e.EventType {
		case domain.GradeRegistered:
			registeredCount++
			if e.Grade == nil {
				t.Fatalf("event %d: GRADE_REGISTERED must have non-nil Grade", i)
			}
			if e.PreviousGrade != nil || e.NewGrade != nil {
				t.Fatalf("event %d: GRADE_REGISTERED must have nil PreviousGrade and NewGrade", i)
			}
			assertGradeValid(t, i, *e.Grade)
			bin := int(math.Round(*e.Grade * 10))
			gradeBuckets[bin]++

		case domain.GradeModified:
			modifiedCount++
			if e.Grade != nil {
				t.Fatalf("event %d: GRADE_MODIFIED must have nil Grade", i)
			}
			if e.PreviousGrade == nil || e.NewGrade == nil {
				t.Fatalf("event %d: GRADE_MODIFIED must have non-nil PreviousGrade and NewGrade", i)
			}
			assertGradeValid(t, i, *e.PreviousGrade)
			assertGradeValid(t, i, *e.NewGrade)
			if *e.PreviousGrade == *e.NewGrade {
				t.Fatalf("event %d: GRADE_MODIFIED PreviousGrade (%.1f) must differ from NewGrade (%.1f)",
					i, *e.PreviousGrade, *e.NewGrade)
			}
			gradeBuckets[int(math.Round(*e.PreviousGrade*10))]++
			gradeBuckets[int(math.Round(*e.NewGrade*10))]++

		default:
			t.Fatalf("event %d: unknown event type %s", i, e.EventType)
		}
	}

	// Verify both types are reasonably represented (around 50% each)
	if registeredCount < 2000 || modifiedCount < 2000 {
		t.Errorf("unbalanced event type distribution: registered=%d, modified=%d",
			registeredCount, modifiedCount)
	}

	// Verify uniform grade distribution across all 51 discrete values (0.0 to 5.0)
	// With 5000 events, total grade observations >= 5000.
	// Average per bin is ~147. Each bin should receive at least 40 occurrences.
	for bin := 0; bin <= 50; bin++ {
		count := gradeBuckets[bin]
		if count < 40 {
			t.Errorf("grade %.1f (bin %d) appeared only %d times (expected >= 40)",
				float64(bin)/10.0, bin, count)
		}
	}
}

func TestSampleEventsJSON(t *testing.T) {
	gen := generator.NewRandomEventGenerator()
	events, err := gen.Generate(10)
	if err != nil {
		t.Fatalf("failed to generate events: %v", err)
	}

	var foundReg, foundMod bool
	for _, e := range events {
		if !foundReg && e.EventType == domain.GradeRegistered {
			foundReg = true
			data, _ := json.MarshalIndent(e, "", "  ")
			t.Logf("\n[Ejemplo GRADE_REGISTERED]:\n%s", string(data))
		}
		if !foundMod && e.EventType == domain.GradeModified {
			foundMod = true
			data, _ := json.MarshalIndent(e, "", "  ")
			t.Logf("\n[Ejemplo GRADE_MODIFIED]:\n%s", string(data))
		}
	}
}

func assertGradeValid(t *testing.T, idx int, val float64) {
	t.Helper()
	if val < 0.0 || val > 5.0 {
		t.Fatalf("event %d: grade %.2f out of bounds [0.0, 5.0]", idx, val)
	}
	// Verify single decimal precision
	scaled := val * 10.0
	if math.Abs(scaled-math.Round(scaled)) > 1e-6 {
		t.Fatalf("event %d: grade %.4f does not have single-decimal precision", idx, val)
	}
}
