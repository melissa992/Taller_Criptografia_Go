package domain

// Log represents a structured collection of academic events bundled for persistence and protection.
type Log struct {
	LogID       string  `json:"log_id"`
	Version     string  `json:"version"`
	GeneratedAt string  `json:"generated_at"`
	EventCount  int     `json:"event_count"`
	Events      []Event `json:"events"`
}

