package domain_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/melissa992/Taller_Criptografia_Go/internal/domain"
)

func sampleGrade(val float64) *float64 {
	return &val
}

func createBaseEvent() domain.Event {
	return domain.Event{
		EventID:     "123e4567-e89b-12d3-a456-426614174000",
		EventType:   domain.GradeRegistered,
		Timestamp:   "2026-11-07T10:00:00Z",
		ActorUID:    "doc-000001",
		StudentUID:  "est-000001",
		CourseUID:   "cur-000001",
		Grade:       sampleGrade(4.5),
		PayloadHash: "initial-hash-value-to-be-ignored",
	}
}

func TestComputePayloadHash_Determinism(t *testing.T) {
	event := createBaseEvent()

	firstHash, err := domain.ComputePayloadHash(event)
	if err != nil {
		t.Fatalf("ComputePayloadHash returned unexpected error: %v", err)
	}

	for i := 0; i < 100; i++ {
		hash, err := domain.ComputePayloadHash(event)
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
		if hash != firstHash {
			t.Fatalf("iteration %d: expected hash %s, got %s", i, firstHash, hash)
		}
	}
}

func TestComputePayloadHash_FormatAndLength(t *testing.T) {
	event := createBaseEvent()
	hash, err := domain.ComputePayloadHash(event)
	if err != nil {
		t.Fatalf("ComputePayloadHash returned error: %v", err)
	}

	if len(hash) != 64 {
		t.Errorf("expected hash length 64, got %d", len(hash))
	}

	bytes, err := hex.DecodeString(hash)
	if err != nil {
		t.Errorf("expected valid hex string, got error: %v", err)
	}
	if len(bytes) != 32 {
		t.Errorf("expected 32 decoded bytes, got %d", len(bytes))
	}
}

func TestComputePayloadHash_PayloadHashFieldIgnored(t *testing.T) {
	e1 := createBaseEvent()
	e1.PayloadHash = "hash-one"

	e2 := createBaseEvent()
	e2.PayloadHash = "completely-different-hash"

	h1, err1 := domain.ComputePayloadHash(e1)
	h2, err2 := domain.ComputePayloadHash(e2)

	if err1 != nil || err2 != nil {
		t.Fatalf("errors computing hashes: %v, %v", err1, err2)
	}

	if h1 != h2 {
		t.Errorf("expected identical hashes regardless of PayloadHash field, got %s != %s", h1, h2)
	}
}

func TestComputePayloadHash_FieldSensitivity(t *testing.T) {
	base := createBaseEvent()
	baseHash, err := domain.ComputePayloadHash(base)
	if err != nil {
		t.Fatalf("failed to compute base hash: %v", err)
	}

	tests := []struct {
		name     string
		modifier func(e *domain.Event)
	}{
		{
			name:     "modify EventID",
			modifier: func(e *domain.Event) { e.EventID = "different-id" },
		},
		{
			name: "modify EventType",
			modifier: func(e *domain.Event) {
				e.EventType = domain.GradeModified
				e.Grade = nil
				e.PreviousGrade = sampleGrade(3.0)
				e.NewGrade = sampleGrade(4.5)
			},
		},
		{
			name:     "modify Timestamp",
			modifier: func(e *domain.Event) { e.Timestamp = "2026-11-07T10:00:01Z" },
		},
		{
			name:     "modify ActorUID",
			modifier: func(e *domain.Event) { e.ActorUID = "doc-999999" },
		},
		{
			name:     "modify StudentUID",
			modifier: func(e *domain.Event) { e.StudentUID = "est-999999" },
		},
		{
			name:     "modify CourseUID",
			modifier: func(e *domain.Event) { e.CourseUID = "cur-999999" },
		},
		{
			name:     "modify Grade",
			modifier: func(e *domain.Event) { e.Grade = sampleGrade(4.6) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modEvent := createBaseEvent()
			tt.modifier(&modEvent)

			modHash, err := domain.ComputePayloadHash(modEvent)
			if err != nil {
				t.Fatalf("ComputePayloadHash failed: %v", err)
			}

			if modHash == baseHash {
				t.Errorf("expected hash to change when modifying field in test '%s', but remained %s", tt.name, baseHash)
			}
		})
	}
}

func TestVerifyPayloadHash_RoundTripJSON(t *testing.T) {
	event := createBaseEvent()
	hash, err := domain.ComputePayloadHash(event)
	if err != nil {
		t.Fatalf("failed to compute hash: %v", err)
	}
	event.PayloadHash = hash

	// Serialize to JSON
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}

	// Deserialize back
	var unmarshaled domain.Event
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal event: %v", err)
	}

	valid, err := domain.VerifyPayloadHash(unmarshaled)
	if err != nil {
		t.Fatalf("VerifyPayloadHash returned error: %v", err)
	}
	if !valid {
		t.Error("expected VerifyPayloadHash to return true after JSON round-trip")
	}
}

func TestVerifyPayloadHash_TamperedEvent(t *testing.T) {
	event := createBaseEvent()
	hash, err := domain.ComputePayloadHash(event)
	if err != nil {
		t.Fatalf("failed to compute hash: %v", err)
	}
	event.PayloadHash = hash

	// Tamper with the grade
	tamperedGrade := 5.0
	event.Grade = &tamperedGrade

	valid, err := domain.VerifyPayloadHash(event)
	if err != nil {
		t.Fatalf("VerifyPayloadHash returned unexpected error: %v", err)
	}
	if valid {
		t.Error("expected VerifyPayloadHash to detect tampering and return false")
	}
}

