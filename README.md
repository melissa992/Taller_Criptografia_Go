# LogGuard — Protección de Logs Estructurados en Reposo

Herramienta de línea de comandos en Go desarrollada para el **Taller Dos de Criptografía (Universidad del Valle)**. LogGuard simula la generación de eventos académicos (registro y modificación de notas) y aplica hashing criptográfico (SHA-256) y cifrado autenticado (AES-256-GCM) para salvaguardar la confidencialidad, integridad y verificabilidad de logs en reposo.

---

## Requisitos Previos

- **Go**: Versión 1.22 o superior instalada.
- **Make** (opcional, para ejecutar comandos rápidos en Linux/macOS/Windows).

---

## Estructura del Proyecto

```text
logguard/
├── cmd/logguard/main.go          # Composition root (inyección de dependencias)
├── internal/
│   ├── domain/                   # Entidades puras y tipos (sin I/O ni dependencias)
│   ├── generator/                # Generador aleatorio de eventos académicos
│   ├── crypto/                   # Primitivas criptográficas estándar (SHA-256, AES-256-GCM)
│   ├── logstore/                 # Persistencia en disco de artefactos generados
│   ├── service/                  # Casos de uso (ProtectionService, VerificationService)
│   └── cli/                      # Interfaz interactiva de terminal (promptui)
├── docs/
│   ├── ARCHITECTURE.md           # Decisiones de diseño criptográfico y justificaciones
│   ├── CONTEXT.md                # Reglas y restricciones para el desarrollo de historias
│   └── diagrams/                 # Diagramas de arquitectura y comportamiento (Mermaid)
├── output/                       # Artefactos criptográficos generados (.gitignore)
├── Makefile                      # Tareas comunes (build, run, test, vet, fmt)
└── go.mod
```

---

## Comandos Disponibles

A través del `Makefile` incluido o mediante comandos nativos de `go`:

```bash
# Compilar el binario
make build
# o manualmente: go build -o logguard ./cmd/logguard

# Ejecutar la aplicación
make run
# o manualmente: go run ./cmd/logguard

# Ejecutar pruebas unitarias
make test
# o manualmente: go test -v ./...

# Análisis estático
make vet
# o manualmente: go vet ./...

# Formateo de código según convenciones Go
make fmt
# o manualmente: gofmt -l -w .
```

---

## Personalización del Módulo

El módulo se encuentra configurado con el placeholder:
```text
module github.com/melissa992/Taller_Criptografia_Go
```

Para adaptarlo a tu usuario personal u organizacional de GitHub:
1. Actualiza la primera línea en `go.mod`.
2. Actualiza los imports internos en los archivos de `cmd/` e `internal/`.

