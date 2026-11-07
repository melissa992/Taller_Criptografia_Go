package domain

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// eventPayload mirrors the exact fields and JSON serialization tags of Event,
// strictly omitting PayloadHash.
//
// Architectural rationale:
//  1. Omission of payload_hash: Prevents circular hash dependency (the hash digest cannot
//     be an input to its own computation).
//  2. Struct vs Map: A Go struct guarantees strict, deterministic key ordering during
//     json.Marshal according to field declaration order. Using map[string]interface{} would
//     introduce runtime sorting overhead and potential serialization inconsistency across platforms.
type eventPayload struct {
	EventID       string    `json:"event_id"`
	EventType     EventType `json:"event_type"`
	Timestamp     string    `json:"timestamp"`
	ActorUID      string    `json:"actor_uid"`
	StudentUID    string    `json:"student_uid"`
	CourseUID     string    `json:"course_uid"`
	Grade         *float64  `json:"grade,omitempty"`
	PreviousGrade *float64  `json:"previous_grade,omitempty"`
	NewGrade      *float64  `json:"new_grade,omitempty"`
}

// ComputePayloadHash calculates a deterministic SHA-256 digest over an event's payload fields,
// strictly excluding the PayloadHash field itself to break cyclic dependency.
// It returns a 64-character lowercase hexadecimal string.
func ComputePayloadHash(e Event) (string, error) {
	p := eventPayload{
		EventID:       e.EventID,
		EventType:     e.EventType,
		Timestamp:     e.Timestamp,
		ActorUID:      e.ActorUID,
		StudentUID:    e.StudentUID,
		CourseUID:     e.CourseUID,
		Grade:         e.Grade,
		PreviousGrade: e.PreviousGrade,
		NewGrade:      e.NewGrade,
	}

	payloadBytes, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("failed to marshal event payload: %w", err)
	}

	digest := sha256.Sum256(payloadBytes)
	return hex.EncodeToString(digest[:]), nil
}

// VerifyPayloadHash recalculates the payload hash of e and compares it against e.PayloadHash
// in constant time to prevent timing attacks.
func VerifyPayloadHash(e Event) (bool, error) {
	computed, err := ComputePayloadHash(e)
	if err != nil {
		return false, fmt.Errorf("failed to compute payload hash during verification: %w", err)
	}

	// ConstantTimeCompare returns 1 if the two slices have equal contents, 0 otherwise.
	if subtle.ConstantTimeCompare([]byte(computed), []byte(e.PayloadHash)) == 1 {
		return true, nil
	}

	return false, nil
}
