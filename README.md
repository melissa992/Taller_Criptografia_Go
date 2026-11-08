# LogGuard — Proteccion de Logs Estructurados en Reposo

Herramienta de linea de comandos en Go desarrollada para el **Taller Dos de Criptografia (Universidad del Valle)**. LogGuard genera eventos academicos (registro y modificacion de notas), calcula hashes SHA-256 por evento y del log completo, cifra el log con AES-256-GCM y verifica la integridad durante la recuperacion. El ciclo completo cubre los 10 pasos del taller.

---

## Requisitos

- **Go 1.22 o superior** instalado y en el `PATH`.
- Entorno principal: **Windows con PowerShell**. Los comandos que siguen estan escritos para PowerShell.
- No se requieren dependencias de sistema adicionales. La unica dependencia externa es `github.com/manifoldco/promptui`, descargada automaticamente por `go mod`.

---

## Instalacion

```powershell
git clone https://github.com/melissa992/Taller_Criptografia_Go.git
cd Taller_Criptografia_Go
go build ./...
```

Verificacion de compilacion, formato y analisis estatico:

```powershell
go build ./...
go vet ./...
gofmt -l .
go test ./... -count=1
```

`gofmt -l .` no produce salida si el codigo esta correctamente formateado.
`go test ./... -count=1` debe mostrar `ok` para los 6 paquetes del modulo.
La bandera `-race` requiere CGO; en entornos Windows sin compilador C, se omite.

---

## Uso

```powershell
go run ./cmd/logguard
```

O con el binario compilado:

```powershell
go build -o logguard.exe ./cmd/logguard
.\logguard.exe
```

El menú interactivo presenta cuatro opciones navegables con las teclas de flecha:

```
Menu Principal - LogGuard
  1. Generar eventos
  2. Proteger lote actual
  3. Verificar log guardado
  4. Salir
```

**Flujo recomendado:** 1 → 2 → 3 → 4

Los artefactos se escriben en el directorio `output/` creado automaticamente en el directorio de trabajo.

---

## Pasos del Taller

| Paso | Descripcion | Paquete | Archivo | Funcion |
|------|-------------|---------|---------|---------|
| 1 | Pedir cantidad de eventos al usuario | `cli` | `internal/cli/menu.go` | `handleGenerateEvents` |
| 2 | Generar n eventos aleatorios (tipo, UIDs, nota) | `generator` | `internal/generator/generator.go` | `RandomEventGenerator.Generate` |
| 3 | Hash SHA-256 del payload de cada evento | `domain` | `internal/domain/payload.go` | `ComputePayloadHash` |
| 4 | Consolidar eventos en log JSON y persistir | `service` | `internal/service/protection.go` | `protectionService.Protect` |
| 5 | Hash SHA-256 del log en claro | `service` | `internal/service/protection.go` | `protectionService.Protect` |
| 6 | Cifrar log con AES-256-GCM y persistir clave | `service` / `crypto` | `internal/service/protection.go` | `protectionService.Protect` |
| 7 | Hash SHA-256 del log cifrado | `service` | `internal/service/protection.go` | `protectionService.Protect` |
| 8 | Descifrar log con AES-256-GCM | `service` / `crypto` | `internal/service/verification.go` | `verificationService.Verify` |
| 9 | Hash SHA-256 del descifrado y comparacion | `service` | `internal/service/verification.go` | `verificationService.Verify` |
| 10 | Reporte final con veredicto de integridad | `service` / `cli` | `internal/service/verification.go` | `verificationService.Verify` |

---

## Artefactos en `output/`

| Archivo | Contenido | Permisos | Paso |
|---------|-----------|----------|------|
| `log.json` | Log JSON consolidado en texto claro | 0644 | 4 |
| `log.sha256` | Hash SHA-256 hexadecimal de `log.json` seguido de salto de linea | 0644 | 5 |
| `key.bin` | Clave simetrica AES-256 cruda (32 bytes) | 0600 | 6 |
| `log.enc` | Log cifrado: `nonce(12 B) \|\| ciphertext \|\| tag(16 B)` | 0644 | 6 |
| `log.enc.sha256` | Hash SHA-256 hexadecimal de `log.enc` seguido de salto de linea | 0644 | 7 |
| `log.dec.json` | Bytes recuperados cuando la verificación de integridad es satisfactoria | 0600 | 9 |

Para verificar un hash de forma manual en PowerShell:

```powershell
Get-FileHash output\log.json -Algorithm SHA256
```

El valor `Hash` devuelto debe coincidir con el contenido de `output\log.sha256` (en mayusculas o minusculas segun la herramienta; el programa almacena minusculas).

---

## Diseno de Seguridad

### SHA-256

Se usa `crypto/sha256` de la biblioteca estandar de Go, implementacion de FIPS 180-4. Proporciona resistencia a preimagen y colisiones con seguridad de 128 bits frente a ataques de cumpleanos. Se aplica en tres niveles:

1. Hash del payload de cada evento (integridad granular, paso 3).
2. Hash del log consolidado en claro (paso 5).
3. Hash del log cifrado (integridad del artefacto binario, paso 7).
4. Hash del descifrado para comparacion con el hash original (verificacion, paso 9).

### AES-256-GCM frente a CBC y ECB

| Propiedad | AES-256-GCM | AES-256-CBC | AES-ECB |
|-----------|-------------|-------------|---------|
| Confidencialidad | Si | Si | No (patrones visibles) |
| Autenticacion integrada (AEAD) | Si (tag 128 bits) | No | No |
| Inmunidad a Padding Oracle | Si (sin relleno) | No sin Encrypt-then-MAC | No aplica |
| Deteccion de manipulacion en disco | Si, inmediata | No | No |

AES-ECB fue descartado porque bloques identicos producen ciphertext identico, filtrando la estructura del JSON. AES-CBC sin MAC deja abiertos ataques de padding oracle. AES-GCM combina cifrado de flujo (CTR) con autenticacion de mensaje (GHASH), de modo que cualquier alteracion de un byte en `log.enc` hace que `Decrypt` rechace el mensaje antes de exponer texto en claro.

### Formato de `log.enc`

```
[ nonce 12 bytes ][ ciphertext ][ tag GCM 16 bytes ]
```

La longitud total es `len(plaintext) + 28`. El nonce se almacena como prefijo publico del archivo; la clave nunca aparece en `log.enc`.

### Hashing a doble nivel

- **Nivel por evento:** `payload_hash` protege la integridad de cada registro de forma individual.
- **Nivel de log:** `log.sha256` protege la integridad del documento completo en claro.
- **Nivel post-descifrado:** comparacion entre `SHA-256(log.dec.json)` y el contenido de `log.sha256` confirma que el descifrado es fiel al original.

### `crypto/rand` frente a `math/rand/v2`

| Uso | Fuente |
|-----|--------|
| Clave AES-256 (32 bytes) | `crypto/rand` |
| Nonce GCM (12 bytes) | `crypto/rand` |
| UUID v4 de eventos y logs | `crypto/rand` |
| Notas, tipos de evento, UIDs simulados | `math/rand/v2` |

Ningun valor producido por `math/rand/v2` se usa como entrada criptografica.

---

## Estructura del Repositorio

```text
Taller_Criptografia_Go/
├── cmd/logguard/main.go          # Raiz de composicion: inyeccion de dependencias y arranque
├── internal/
│   ├── domain/                   # Entidades puras (Event, Log, Report) sin I/O ni dependencias internas
│   ├── generator/                # Generador aleatorio de eventos academicos
│   ├── crypto/                   # Primitivas criptograficas: SHA-256 y AES-256-GCM
│   ├── logstore/                 # Persistencia de artefactos en disco (FileStore, constantes de nombre)
│   ├── service/                  # Casos de uso: ProtectionService y VerificationService
│   └── cli/                      # Interfaz interactiva (promptui), Presenter y validadores
├── docs/
│   ├── ARCHITECTURE.md           # Diseno criptografico y decisiones de arquitectura
│   ├── CONTEXT.md                # Reglas de desarrollo del taller
│   ├── FICHA_TECNICA.md          # Ficha tecnica verificada con fragmentos de codigo
│   └── diagrams/                 # Diagramas Mermaid (structure.mmd, behavior.mmd)
├── output/                       # Artefactos generados en ejecucion (en .gitignore)
├── Makefile                      # Atajos opcionales para build, run, test, vet, fmt
└── go.mod
```

**Regla de dependencias por capa** (arquitectura por capas con inversion de dependencias):

| Paquete | Puede importar | No puede importar |
|---------|---------------|-------------------|
| `domain` | Solo stdlib | Ningun paquete interno |
| `crypto` / `generator` / `logstore` | `domain`, stdlib | `service`, `cli` |
| `service` | `domain`, `crypto`, `logstore`, stdlib | `generator`, `cli` |
| `cli` | `domain`, `generator`, `service`, `promptui` | `crypto`, `logstore` |
| `cmd/logguard` | Todos los anteriores | — |

Para verificar que `service` no importa `generator`:

```powershell
go list -f "{{.Imports}}" ./internal/service
```

La salida no debe contener `generator`.

---

## Historias de Usuario

| Historia | Pasos del taller | Paquetes principales |
|----------|-----------------|----------------------|
| HU-1: Generacion de eventos con integridad por registro | 1, 2, 3 | `domain`, `generator`, `cli` |
| HU-2: Consolidacion, hash y cifrado del log en reposo | 4, 5, 6, 7 | `crypto`, `logstore`, `service`, `cli` |
| HU-3: Verificación de integridad | 8, 9, 10 | `service`, `logstore`, `cli` |

---

## Pruebas

```powershell
go test ./... -count=1
```

Ejecuta las pruebas de los 6 paquetes del modulo. La bandera `-count=1` desactiva el cache de resultados para garantizar ejecucion real. La bandera `-race` requiere CGO y no esta disponible en todos los entornos Windows sin compilador C instalado.

Para ver detalle de cada prueba solo si hay fallos:

```powershell
go test ./... -count=1 -v
```

## Verificar un log protegido

1. Ejecuta `go run ./cmd/logguard` desde la raíz del proyecto.
2. Elige **Generar eventos** e indica la cantidad. El lote queda en memoria.
3. Elige **Proteger lote actual** y confirma el guardado. La CLI reemplaza los archivos de protección que ya existan en `output/`.
4. Elige **Verificar log guardado**. Puedes ir directamente a esta opción al reiniciar la CLI con los artefactos de protección en `output/`.

El reporte muestra el total de eventos y su desglose por tipo, los tres SHA-256 y el veredicto de integridad. Si los hashes coinciden y el descifrado se autentica, la CLI escribe los bytes recuperados en `output/log.dec.json`.

Consulta los diagramas de [estructura](docs/diagrams/structure.mmd) y [comportamiento](docs/diagrams/behavior.mmd) en Mermaid.

---

## Diagramas

Los diagramas Mermaid se encuentran en `docs/diagrams/`:

- `structure.mmd`: diagrama de clases completo del sistema.
- `behavior.mmd`: diagrama de secuencia con los 10 pasos del taller.

Para exportar a imagen se puede usar la CLI de Mermaid si esta disponible:

```powershell
# Si mmdc esta instalado globalmente como herramienta Node.js:
mmdc -i docs\diagrams\structure.mmd -o docs\diagrams\structure.png
mmdc -i docs\diagrams\behavior.mmd -o docs\diagrams\behavior.png
```

La ejecucion de `npx @mermaid-js/mermaid-cli` puede estar bloqueada por la politica de ejecucion de PowerShell. En ese caso, la alternativa es pegar el contenido del archivo `.mmd` directamente en [mermaid.live](https://mermaid.live) para visualizarlo o exportarlo.

---

## Limitaciones Conocidas

- **Permisos de `key.bin` en Windows:** `os.WriteFile` con modo `0600` no configura ACLs de Windows del mismo modo que en POSIX. El archivo hereda los permisos del directorio contenedor. En produccion se debe usar un KMS o HSM.
- **Clave en archivo local:** almacenar la clave en el mismo directorio que los datos cifrados reduce la defensa en profundidad. En produccion se recomienda *Envelope Encryption* con un servicio externo de gestion de claves.
- **Artefactos parciales ante fallo:** si `Protect` falla en un paso intermedio, los artefactos ya escritos permanecen en disco como estado invalido. La siguiente ejecucion exitosa los sobreescribe por completo.

---

## Uso de Inteligencia Artificial

Este proyecto se desarrollo con asistencia de **Antigravity** (asistente de codificacion) y un asistente de chat de IA. Las contribuciones de IA incluyeron: diseno inicial de la arquitectura, generacion de codigo de stubs e implementaciones, generacion de pruebas unitarias y redaccion de documentacion. Todas las salidas fueron verificadas manualmente: ejecucion de pruebas con `go test`, verificacion de hashes con `Get-FileHash` en PowerShell, revision de planes y diffs antes de aplicar cambios.
