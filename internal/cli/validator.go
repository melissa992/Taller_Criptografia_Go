package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/melissa992/Taller_Criptografia_Go/internal/generator"
)

// ValidateEventCount validates user input string for the number of events to generate.
func ValidateEventCount(input string) error {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return errors.New("la cantidad no puede estar vacía")
	}

	n, err := strconv.Atoi(trimmed)
	if err != nil {
		return errors.New("debe ingresar un número entero válido")
	}

	if n < 1 {
		return errors.New("la cantidad de eventos debe ser al menos 1")
	}

	if n > generator.MaxEvents {
		return fmt.Errorf("la cantidad de eventos no puede superar %d", generator.MaxEvents)
	}

	return nil
}
