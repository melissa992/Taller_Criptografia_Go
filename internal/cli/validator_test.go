package cli_test

import (
	"testing"

	"github.com/melissa992/Taller_Criptografia_Go/internal/cli"
)

func TestValidateEventCount(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid inputs
		{name: "minimum allowed", input: "1", wantErr: false},
		{name: "typical small value", input: "10", wantErr: false},
		{name: "typical medium value", input: "500", wantErr: false},
		{name: "maximum allowed", input: "10000", wantErr: false},
		{name: "valid with whitespace padding", input: "  250  ", wantErr: false},

		// Invalid inputs
		{name: "empty string", input: "", wantErr: true},
		{name: "only spaces", input: "   ", wantErr: true},
		{name: "non-numeric alphabetic", input: "abc", wantErr: true},
		{name: "alphanumeric", input: "10events", wantErr: true},
		{name: "floating point", input: "4.5", wantErr: true},
		{name: "zero", input: "0", wantErr: true},
		{name: "negative value", input: "-1", wantErr: true},
		{name: "large negative value", input: "-500", wantErr: true},
		{name: "one above maximum", input: "10001", wantErr: true},
		{name: "far above maximum", input: "999999", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cli.ValidateEventCount(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEventCount(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
