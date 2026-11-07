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
	hasher := crypto.NewSHA256Hasher()
	encryptor := crypto.NewAESGCMEncryptor()
	store := logstore.NewFileStore("./output")
	gen := generator.NewRandomEventGenerator()

	protectionSvc := service.NewProtectionService(gen, hasher, encryptor, store)
	verificationSvc := service.NewVerificationService(hasher, encryptor, store)
	presenter := cli.NewPresenter()

	menu := cli.NewMenu(protectionSvc, verificationSvc, presenter)
	if err := menu.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

