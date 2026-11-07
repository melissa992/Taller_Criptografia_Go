// Package domain contains pure domain entities, value objects, and business types
// with zero external dependencies and no I/O operations.
package domain

// EventType defines the category of an academic event.
type EventType string

const (
	// GradeRegistered indicates the initial registration of an academic grade.
	GradeRegistered EventType = "GRADE_REGISTERED"
	// GradeModified indicates an alteration or update to a previously registered grade.
	GradeModified EventType = "GRADE_MODIFIED"
)

// Event models an individual academic log record.
type Event struct {
	EventID       string    `json:"event_id"`
	EventType     EventType `json:"event_type"`
	Timestamp     string    `json:"timestamp"` // RFC3339 format
	ActorUID      string    `json:"actor_uid"`
	StudentUID    string    `json:"student_uid"`
	CourseUID     string    `json:"course_uid"`
	Grade         *float64  `json:"grade,omitempty"`
	PreviousGrade *float64  `json:"previous_grade,omitempty"`
	NewGrade      *float64  `json:"new_grade,omitempty"`
	PayloadHash   string    `json:"payload_hash"`
}

