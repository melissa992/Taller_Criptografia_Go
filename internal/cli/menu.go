package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/melissa992/Taller_Criptografia_Go/internal/domain"
	"github.com/melissa992/Taller_Criptografia_Go/internal/generator"
	"github.com/melissa992/Taller_Criptografia_Go/internal/service"
)

// Session retains state across menu operations in memory.
type Session struct {
	Events         []domain.Event
	protectedLogID string
	verified       bool
}

const (
	generateOption = iota
	protectOption
	verifyOption
	exitOption
)

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
				Title:  "Generar eventos",
				Action: m.handleGenerateEvents,
			},
			{
				Title:  "Proteger lote actual",
				Action: m.handleProtectLog,
			},
			{
				Title:  "Verificar log guardado",
				Action: m.handleVerifyLog,
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

		status, next := m.session.menuStatus()
		fmt.Printf("\nLogGuard · %s\n", status)
		prompt := promptui.Select{
			Label:        "Usa ↑/↓ para moverte y Enter para elegir",
			Items:        labels,
			Size:         len(labels),
			CursorPos:    next,
			HideHelp:     true,
			HideSelected: true,
		}

		index, _, err := prompt.Run()
		if err != nil {
			if errors.Is(err, promptui.ErrInterrupt) || errors.Is(err, promptui.ErrEOF) {
				fmt.Println("\nSaliendo de LogGuard.")
				return nil
			}
			return fmt.Errorf("error al desplegar menú principal: %w", err)
		}

		if index == exitOption {
			return items[index].Action()
		}

		if err := items[index].Action(); err != nil {
			fmt.Printf("\n[ERROR] %v\n\n", err)
		}
	}
}

func (s *Session) menuStatus() (string, int) {
	switch {
	case s.verified:
		return "Integridad del log guardado verificada.", exitOption
	case len(s.Events) == 0:
		return "Puedes generar eventos o verificar un log guardado.", generateOption
	case s.protectedLogID == "":
		return fmt.Sprintf("Lote en memoria, pendiente de proteger. Eventos: %d.", len(s.Events)), protectOption
	default:
		return fmt.Sprintf("Lote guardado, pendiente de verificar. Eventos: %d.", len(s.Events)), verifyOption
	}
}

func (m *Menu) handleGenerateEvents() error {
	if len(m.session.Events) > 0 {
		fmt.Println("\nEl nuevo lote reemplazará los eventos en memoria.")
	}
	fmt.Println("Pulsa Ctrl+C para volver al menú.")
	prompt := promptui.Prompt{
		Label:    fmt.Sprintf("Cantidad de eventos (1 a %d)", generator.MaxEvents),
		Validate: ValidateEventCount,
	}

	input, err := prompt.Run()
	if err != nil {
		if errors.Is(err, promptui.ErrInterrupt) || errors.Is(err, promptui.ErrEOF) {
			fmt.Println("\nGeneración cancelada. Volviendo al menú.")
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

	*m.session = Session{Events: events}
	return m.presenter.PresentGeneratedEvents(events)
}

func (m *Menu) handleProtectLog() error {
	if len(m.session.Events) == 0 {
		fmt.Println("\nGenera un lote con la opción 1 antes de protegerlo.")
		return nil
	}

	fmt.Println("\nEsta operación reemplaza los archivos de protección que ya existan en output/.")
	prompt := promptui.Select{
		Label:        fmt.Sprintf("¿Cifrar y guardar el lote actual? Total de eventos: %d", len(m.session.Events)),
		Items:        []string{"Volver al menú", "Proteger y guardar"},
		HideHelp:     true,
		HideSelected: true,
	}
	index, _, err := prompt.Run()
	if errors.Is(err, promptui.ErrInterrupt) || errors.Is(err, promptui.ErrEOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("error al confirmar la protección: %w", err)
	}
	if index == 0 {
		return nil
	}

	m.session.protectedLogID = ""
	m.session.verified = false
	res, err := m.protectionService.Protect(m.session.Events)
	if err != nil {
		return fmt.Errorf("falla durante la protección del log: %w", err)
	}

	m.session.protectedLogID = res.LogID
	return m.presenter.PresentProtection(res)
}

func (m *Menu) handleVerifyLog() error {
	if len(m.session.Events) > 0 && m.session.protectedLogID == "" {
		fmt.Println("\nSe verificará el log de output/. El lote en memoria sigue pendiente de proteger.")
	}
	m.session.verified = false
	report, err := m.verificationService.Verify()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("faltan archivos para verificar el log en output/. Genera y protege un lote con las opciones 1 y 2.\nDetalle: %w", err)
		}
		return fmt.Errorf("integridad no comprobada: %w", err)
	}
	m.session.verified = report.IntegrityPreserved && (len(m.session.Events) == 0 || report.LogID == m.session.protectedLogID)
	return m.presenter.PresentReport(report)
}
