package domain

import "errors"

// ComputePayloadHash calculates a deterministic SHA-256 hash over an event's payload fields,
// strictly excluding the PayloadHash field itself to break cyclic dependency.
func ComputePayloadHash(e Event) (string, error) {
	return "", errors.New("not implemented")
}

