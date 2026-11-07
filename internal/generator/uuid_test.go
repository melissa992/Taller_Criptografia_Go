package generator

import (
	"regexp"
	"testing"
)

var uuidV4Regex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestGenerateUUIDv4_FormatAndUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	const count = 500

	for i := 0; i < count; i++ {
		uuid, err := generateUUIDv4()
		if err != nil {
			t.Fatalf("unexpected error generating UUID v4: %v", err)
		}

		if len(uuid) != 36 {
			t.Errorf("expected 36 characters, got %d for %s", len(uuid), uuid)
		}

		if !uuidV4Regex.MatchString(uuid) {
			t.Errorf("UUID %s does not match RFC 4122 v4 pattern", uuid)
		}

		if seen[uuid] {
			t.Fatalf("duplicate UUID generated: %s", uuid)
		}
		seen[uuid] = true
	}
}
