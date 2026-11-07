package domain

// Report summarizes the result of the log verification process across all cryptographic stages.
type Report struct {
	LogID              string            `json:"log_id"`
	EventCount         int               `json:"event_count"`
	EventsByType       map[EventType]int `json:"events_by_type"`
	PlainLogHash       string            `json:"plain_log_hash"`
	EncryptedLogHash   string            `json:"encrypted_log_hash"`
	DecryptedLogHash   string            `json:"decrypted_log_hash"`
	IntegrityPreserved bool              `json:"integrity_preserved"`
	Details            string            `json:"details,omitempty"`
}

