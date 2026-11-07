// Package cli handles terminal input capture and formatted output presentation,
// providing an interactive menu using promptui.
package cli

import (
	"errors"

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

