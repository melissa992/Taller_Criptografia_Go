// Package main is the composition root for the LogGuard CLI application.
// It wires together concrete implementations and starts the user interface.
package main

import (
	"fmt"
	"os"

	"github.com/melissa992/Taller_Criptografia_Go/internal/cli"
	"github.com/melissa992/Taller_Criptografia_Go/internal/crypto"
	"github.com/melissa992/Taller_Criptografia_Go/internal/generator"
	"github.com/melissa992/Taller_Criptografia_Go/internal/logstore"
	"github.com/melissa992/Taller_Criptografia_Go/internal/service"
)

func main() {
	// --- HU-1: Generación de eventos ---
	gen := generator.NewRandomEventGenerator()

	// --- HU-2: Consolidación, hash y cifrado ---
	hasher := crypto.NewSHA256Hasher()
	encryptor := crypto.NewAESGCMEncryptor()
	store := logstore.NewFileStore("./output")
	protectionSvc := service.NewProtectionService(hasher, encryptor, store, service.WithIDFunc(generator.NewUUIDv4))

	// --- HU-3: Verificación e integridad (stub) ---
	verificationSvc := service.NewVerificationService(hasher, encryptor, store)

	// Presentation layer and CLI menu
	presenter := cli.NewPresenter()
	menu := cli.NewMenu(protectionSvc, verificationSvc, presenter, gen)

	if err := menu.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error fatal en LogGuard: %v\n", err)
		os.Exit(1)
	}
}
