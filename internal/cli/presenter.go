// Package cli handles terminal input capture and formatted output presentation,
// providing an interactive menu using promptui.
package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/melissa992/Taller_Criptografia_Go/internal/domain"
	"github.com/melissa992/Taller_Criptografia_Go/internal/service"
)

// Presenter formats and outputs domain models, protection summaries, and verification reports to stdout.
type Presenter struct{}

// NewPresenter constructs a new Presenter instance.
func NewPresenter() *Presenter {
	return &Presenter{}
}

// PresentProtection renders the protection result summary to the console.
func (p *Presenter) PresentProtection(res service.ProtectionResult) error {
	return errors.New("not implemented")
}

// PresentReport renders the final verification report and integrity verdict to the console.
func (p *Presenter) PresentReport(rep domain.Report) error {
	return errors.New("not implemented")
}

// PresentGeneratedEvents displays summary metrics and a preview table of the first 5 generated events.
func (p *Presenter) PresentGeneratedEvents(events []domain.Event) error {
	total := len(events)
	if total == 0 {
		fmt.Println("\nNo se generaron eventos.")
		return nil
	}

	var registeredCount, modifiedCount int
	for _, e := range events {
		switch e.EventType {
		case domain.GradeRegistered:
			registeredCount++
		case domain.GradeModified:
			modifiedCount++
		}
	}

	fmt.Println("\n=========================================================================================")
	fmt.Println("                       RESUMEN DE GENERACIÓN DE EVENTOS                                  ")
	fmt.Println("=========================================================================================")
	fmt.Printf(" Total de eventos generados:   %d\n", total)
	fmt.Printf(" - Registros de nota:          %d (GRADE_REGISTERED)\n", registeredCount)
	fmt.Printf(" - Modificaciones de nota:     %d (GRADE_MODIFIED)\n", modifiedCount)
	fmt.Println("-----------------------------------------------------------------------------------------")
	fmt.Println(" Primeros 5 eventos generados (vista previa):")
	fmt.Println("-----------------------------------------------------------------------------------------")
	fmt.Printf("%-10s | %-16s | %-10s | %-10s | %-10s | %-14s | %-14s\n",
		"ID Corto", "Tipo Evento", "Actor", "Estudiante", "Curso", "Calificación", "Hash Payload (12)")
	fmt.Println(strings.Repeat("-", 89))

	previewLimit := 5
	if total < previewLimit {
		previewLimit = total
	}

	for i := 0; i < previewLimit; i++ {
		e := events[i]

		shortID := e.EventID
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}

		var gradeStr string
		if e.EventType == domain.GradeRegistered && e.Grade != nil {
			gradeStr = fmt.Sprintf("%.1f", *e.Grade)
		} else if e.EventType == domain.GradeModified && e.PreviousGrade != nil && e.NewGrade != nil {
			gradeStr = fmt.Sprintf("%.1f -> %.1f", *e.PreviousGrade, *e.NewGrade)
		}

		shortHash := e.PayloadHash
		if len(shortHash) > 12 {
			shortHash = shortHash[:12] + "..."
		}

		fmt.Printf("%-10s | %-16s | %-10s | %-10s | %-10s | %-14s | %-14s\n",
			shortID, e.EventType, e.ActorUID, e.StudentUID, e.CourseUID, gradeStr, shortHash)
	}

	fmt.Println("=========================================================================================")
	fmt.Println()
	return nil
}
