// Package cli handles terminal input capture and formatted output presentation,
// providing an interactive menu using promptui.
package cli

import (
	"fmt"
	"strings"

	"github.com/melissa992/Taller_Criptografia_Go/internal/domain"
	"github.com/melissa992/Taller_Criptografia_Go/internal/logstore"
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
	fmt.Println("\n2. Lote protegido")
	fmt.Printf("Log %s\n", res.LogID)
	fmt.Printf("Eventos guardados: %d · Registros: %d · Modificaciones: %d\n", res.EventCount,
		res.EventsByType[domain.GradeRegistered], res.EventsByType[domain.GradeModified])
	fmt.Printf("Archivos en output/: %s\n", strings.Join(res.ArtifactFiles, ", "))
	fmt.Printf("SHA-256 del original (%s)\n  %s\n", logstore.LogFile, res.PlainLogHash)
	fmt.Printf("SHA-256 del cifrado (%s)\n  %s\n", logstore.EncryptedLogFile, res.EncryptedLogHash)
	return nil
}

// PresentReport renders the final verification report and integrity verdict to the console.
func (p *Presenter) PresentReport(rep domain.Report) error {
	fmt.Println("\n3. Reporte de integridad")
	if rep.IntegrityPreserved {
		fmt.Printf("[OK] Integridad preservada. Recuperado en output/%s.\n", logstore.DecryptedLogFile)
	} else {
		fmt.Println("[FALLO] Integridad no preservada.")
		fmt.Printf("Si existe output/%s, corresponde a un intento anterior.\n", logstore.DecryptedLogFile)
	}
	fmt.Println(rep.Details)
	fmt.Printf("Log %s\n", rep.LogID)
	fmt.Printf("Eventos recuperados: %d · Registros: %d · Modificaciones: %d\n", rep.EventCount,
		rep.EventsByType[domain.GradeRegistered], rep.EventsByType[domain.GradeModified])
	fmt.Printf("SHA-256 original (referencia de %s)\n  %s\n", logstore.LogHashFile, rep.PlainLogHash)
	fmt.Printf("SHA-256 del cifrado (%s, cotejado con %s)\n  %s\n", logstore.EncryptedLogFile, logstore.EncryptedHashFile, rep.EncryptedLogHash)
	fmt.Printf("SHA-256 del descifrado\n  %s\n", rep.DecryptedLogHash)
	return nil
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

	fmt.Println("\n1. Eventos generados")
	fmt.Printf("Eventos generados: %d · Registros: %d · Modificaciones: %d\n", total, registeredCount, modifiedCount)
	previewLimit := min(5, total)
	fmt.Printf("Vista previa (%d de %d)\n", previewLimit, total)
	const row = "%-8s  %-8s  %-10s  %-10s  %-10s  %-10s  %s\n"
	fmt.Printf(row, "ID", "Acción", "Docente", "Estudiante", "Curso", "Nota", "SHA-256 (12)")
	for _, e := range events[:previewLimit] {
		shortID := e.EventID
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}

		action := string(e.EventType)
		var gradeStr string
		switch e.EventType {
		case domain.GradeRegistered:
			action = "Registro"
			if e.Grade != nil {
				gradeStr = fmt.Sprintf("%.1f", *e.Grade)
			}
		case domain.GradeModified:
			action = "Cambio"
			if e.PreviousGrade != nil && e.NewGrade != nil {
				gradeStr = fmt.Sprintf("%.1f → %.1f", *e.PreviousGrade, *e.NewGrade)
			}
		}

		shortHash := e.PayloadHash
		if len(shortHash) > 12 {
			shortHash = shortHash[:12] + "…"
		}

		fmt.Printf(row, shortID, action, e.ActorUID, e.StudentUID, e.CourseUID, gradeStr, shortHash)
	}

	return nil
}
