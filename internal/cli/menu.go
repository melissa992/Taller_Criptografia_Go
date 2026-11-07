package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/melissa992/Taller_Criptografia_Go/internal/domain"
	"github.com/melissa992/Taller_Criptografia_Go/internal/generator"
	"github.com/melissa992/Taller_Criptografia_Go/internal/service"
)

// Session retains state across menu operations in memory.
type Session struct {
	Events []domain.Event
}

type menuItem struct {
	Title  string
	Action func() error
}

// Menu provides an interactive terminal user interface for the LogGuard workflow.
type Menu struct {
	protectionService   service.ProtectionService
	verificationService service.VerificationService
	presenter           *Presenter
	generator           generator.EventGenerator
	session             *Session
}

// NewMenu constructs a new Menu instance maintaining backward compatibility
// with existing parameters and accepting generator at the end.
func NewMenu(
	protection service.ProtectionService,
	verification service.VerificationService,
	presenter *Presenter,
	gen generator.EventGenerator,
) *Menu {
	return &Menu{
		protectionService:   protection,
		verificationService: verification,
		presenter:           presenter,
		generator:           gen,
		session:             &Session{},
	}
}

// Run executes the main interactive loop of the CLI menu.
func (m *Menu) Run() error {
	for {
		items := []menuItem{
			{
				Title:  "Generar eventos de log",
				Action: m.handleGenerateEvents,
			},
			{
				Title:  "Proteger log (consolidar, hash y cifrar)",
				Action: m.handleProtectLog,
			},
			{
				Title: "Salir",
				Action: func() error {
					fmt.Println("\nSaliendo de LogGuard. ¡Hasta luego!")
					return nil
				},
			},
		}

		labels := make([]string, len(items))
		for i, item := range items {
			labels[i] = fmt.Sprintf("%d. %s", i+1, item.Title)
		}

		prompt := promptui.Select{
			Label: "Menú Principal - LogGuard",
			Items: labels,
			Size:  5,
		}

		index, _, err := prompt.Run()
		if err != nil {
			if errors.Is(err, promptui.ErrInterrupt) || errors.Is(err, promptui.ErrEOF) {
				fmt.Println("\nOperación cancelada por el usuario. Saliendo...")
				return nil
			}
			return fmt.Errorf("error al desplegar menú principal: %w", err)
		}

		// Exit option is always the last item
		if index == len(items)-1 {
			return items[index].Action()
		}

		if err := items[index].Action(); err != nil {
			fmt.Printf("\n[ERROR] %v\n\n", err)
		}
	}
}

func (m *Menu) handleGenerateEvents() error {
	prompt := promptui.Prompt{
		Label:    "Cantidad de eventos a generar",
		Validate: ValidateEventCount,
	}

	input, err := prompt.Run()
	if err != nil {
		if errors.Is(err, promptui.ErrInterrupt) || errors.Is(err, promptui.ErrEOF) {
			fmt.Println("\nOperación de generación cancelada.")
			return nil
		}
		return fmt.Errorf("error al capturar cantidad de eventos: %w", err)
	}

	n, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil {
		return fmt.Errorf("error inesperado al convertir cantidad: %w", err)
	}

	events, err := m.generator.Generate(n)
	if err != nil {
		return fmt.Errorf("falla durante la generación de eventos: %w", err)
	}

	m.session.Events = events
	return m.presenter.PresentGeneratedEvents(events)
}

func (m *Menu) handleProtectLog() error {
	if len(m.session.Events) == 0 {
		fmt.Println("\n[AVISO] Primero debes generar eventos de log (opción 1).")
		return nil
	}

	res, err := m.protectionService.Protect(m.session.Events)
	if err != nil {
		return fmt.Errorf("falla durante la protección del log: %w", err)
	}

	return m.presenter.PresentProtection(res)
}
