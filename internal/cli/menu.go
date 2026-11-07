package cli

import (
	"errors"

	"github.com/manifoldco/promptui"
	"github.com/melissa992/Taller_Criptografia_Go/internal/service"
)

// Menu provides an interactive terminal user interface for the LogGuard workflow.
type Menu struct {
	protectionService   service.ProtectionService
	verificationService service.VerificationService
	presenter           *Presenter
	prompt              promptui.Select
}

// NewMenu constructs a new Menu instance with wired services and presenter.
func NewMenu(
	protection service.ProtectionService,
	verification service.VerificationService,
	presenter *Presenter,
) *Menu {
	return &Menu{
		protectionService:   protection,
		verificationService: verification,
		presenter:           presenter,
	}
}

// Run executes the main interactive loop of the CLI menu.
func (m *Menu) Run() error {
	return errors.New("not implemented")
}

