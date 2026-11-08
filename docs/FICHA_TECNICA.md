# Ficha Técnica — LogGuard: Protección de Logs Estructurados en Reposo

Documento técnico elaborado a partir de hechos y firmas verificadas del código fuente actual.
Cubre las fases implementadas **HU-1**, **HU-2** y **HU-3**.

---

## A. HU-1: Generación de eventos con integridad por registro

### 1. Esquema JSON de un evento y manejo de campos
Definido en `internal/domain/event.go: type Event struct`.

Los campos `grade`, `previous_grade` y `new_grade` son punteros (`*float64`) con el tag `omitempty`.
**Razón técnica:** En Go, un valor primitivo `float64` con valor `0.0` coincide con su *zero value*. Si no fuese un puntero, el tag `omitempty` omitiría del JSON serializado las calificaciones legítimas iguales a `0.0`. Al declararse como puntero (`*float64`), solo se omite cuando el puntero es `nil`, garantizando que una nota de `0.0` se preserve explícitamente en el JSON (`0` o `0.0`).

#### Ejemplo real de `GRADE_REGISTERED`
Generado mediante `internal/generator/generator.go: (*RandomEventGenerator).Generate`:
```json
{
  "event_id": "40d0e492-b132-4e69-b76f-2c228a927eb0",
  "event_type": "GRADE_REGISTERED",
  "timestamp": "2026-11-08T00:52:35Z",
  "actor_uid": "doc-990860",
  "student_uid": "est-d7dc48",
  "course_uid": "cur-9c8925",
  "grade": 1.3,
  "payload_hash": "006532ac0afac3c3147e4d7c4555172e748a661ccabb98f273444bd185e2c16a"
}
```

#### Ejemplo real de `GRADE_MODIFIED`
Generado mediante `internal/generator/generator.go: (*RandomEventGenerator).Generate`:
```json
{
  "event_id": "3dc644ee-15ed-4cce-8796-bbf052c13814",
  "event_type": "GRADE_MODIFIED",
  "timestamp": "2026-11-08T00:52:37Z",
  "actor_uid": "doc-5fb823",
  "student_uid": "est-2bd575",
  "course_uid": "cur-9c8925",
  "previous_grade": 4.4,
  "new_grade": 1.9,
  "payload_hash": "1fcdcbe175119a595c1fad68ea1664b0f96dbe0728e47de6917b7842f4b6aef9"
}
```

---

### 2. Payload y función de Hash
Definido en `internal/domain/payload.go`.

- **Campos del payload y orden:** `EventID`, `EventType`, `Timestamp`, `ActorUID`, `StudentUID`, `CourseUID`, `Grade`, `PreviousGrade`, `NewGrade`.
- **Exclusión de `payload_hash`:** Se omite para romper la circularidad autorreferencial; de lo contrario, el valor del hash alteraría el payload que intenta verificar.
- **Uso de struct frente a map:** En Go, los campos de una estructura (`struct`) son serializados por `json.Marshal` en un orden fijo y determinista según su declaración. Un `map[string]interface{}` introduce costos adicionales de ordenamiento de claves y no garantiza la misma inmutabilidad semántica.

#### Fragmento de `internal/domain/payload.go: ComputePayloadHash`
```go
func ComputePayloadHash(e Event) (string, error) {
	p := eventPayload{
		EventID:       e.EventID,
		EventType:     e.EventType,
		Timestamp:     e.Timestamp,
		ActorUID:      e.ActorUID,
		StudentUID:    e.StudentUID,
		CourseUID:     e.CourseUID,
		Grade:         e.Grade,
		PreviousGrade: e.PreviousGrade,
		NewGrade:      e.NewGrade,
	}

	payloadBytes, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("failed to marshal event payload: %w", err)
	}

	digest := sha256.Sum256(payloadBytes)
	return hex.EncodeToString(digest[:]), nil
}
```

---

### 3. Simulación de datos y aleatoriedad
Implementado en `internal/generator/generator.go` y `internal/generator/uuid.go`.

- **Distribución de notas:** Valores discretos en $\{0.0, 0.1, \dots, 5.0\}$ mediante `float64(rng.IntN(51)) / 10.0`.
  - **Justificación de uniformidad:** Redondear un número flotante continuo daría a los extremos $0.0$ y $5.0$ la mitad de probabilidad (intervalos $[0.0, 0.05)$ y $[4.95, 5.0]$ de ancho $0.05$) respecto a valores interiores (ancho $0.10$). El muestreo discreto sobre 51 valores asigna una probabilidad idéntica ($1/51 \approx 1.96\%$) a cada nota.
- **Pool de UIDs simulados:**
  - Actores (profesores): pool fijo de 5 docentes con formato `doc-XXXXXX`.
  - Estudiantes: pool fijo de 20 estudiantes con formato `est-XXXXXX`.
  - Cursos: pool fijo de 5 asignaturas con formato `cur-XXXXXX`.
  - `XXXXXX` corresponde a 6 dígitos hexadecimales generados con `rng.IntN(0x1000000)`.
- **Origen de aleatoriedad de datos:** `math/rand/v2` con generador `rand.NewPCG(s1, s2)` donde las semillas iniciales se extraen de `crypto/rand` en `NewRandomEventGenerator`.
- **Generación de UUID v4:** Función `internal/generator/uuid.go: NewUUIDv4()`, implementada usando 16 bytes de `crypto/rand.Read`, ajustando el bit de versión `b[6] = (b[6] & 0x0f) | 0x40` y la variante RFC 4122 `b[8] = (b[8] & 0x3f) | 0x80`.

---

### 4. Validación de la cantidad de eventos
Implementado en `internal/cli/validator.go: ValidateEventCount(input string) error`.

- **Rango permitido:** Entre `1` y `10000` (definido por constante `generator.MaxEvents = 10000`).
- **Mensajes de error exactos:**
  - Cadena vacía o solo espacios: `"la cantidad no puede estar vacía"`
  - Caracteres no enteros: `"debe ingresar un número entero válido"`
  - Menor a 1: `"la cantidad de eventos debe ser al menos 1"`
  - Mayor a 10000: `"la cantidad de eventos no puede superar 10000"`

---

## B. HU-2: Consolidación, hash y cifrado

### 5. Esquema JSON real del log consolidado
Definido en `internal/domain/log.go: type Log struct`.

Ejemplo real serializado con `json.MarshalIndent`:
```json
{
  "log_id": "7f8b91a2-5c34-4d89-9a1b-0e123456789a",
  "version": "1.0",
  "generated_at": "2026-11-08T00:52:35Z",
  "event_count": 2,
  "events": [
    {
      "event_id": "40d0e492-b132-4e69-b76f-2c228a927eb0",
      "event_type": "GRADE_REGISTERED",
      "timestamp": "2026-11-08T00:52:35Z",
      "actor_uid": "doc-990860",
      "student_uid": "est-d7dc48",
      "course_uid": "cur-9c8925",
      "grade": 1.3,
      "payload_hash": "006532ac0afac3c3147e4d7c4555172e748a661ccabb98f273444bd185e2c16a"
    },
    {
      "event_id": "3dc644ee-15ed-4cce-8796-bbf052c13814",
      "event_type": "GRADE_MODIFIED",
      "timestamp": "2026-11-08T00:52:37Z",
      "actor_uid": "doc-5fb823",
      "student_uid": "est-2bd575",
      "course_uid": "cur-9c8925",
      "previous_grade": 4.4,
      "new_grade": 1.9,
      "payload_hash": "1fcdcbe175119a595c1fad68ea1664b0f96dbe0728e47de6917b7842f4b6aef9"
    }
  ]
}
```

---

### 6. Flujo de los pasos 4 a 7
Orquestado en `internal/service/protection.go: (*protectionService).Protect(events []domain.Event)`.

1. **Paso 4 (Consolidar y guardar log en claro):**
   - Construye `domain.Log` con `log_id` obtenido de `s.newID()` y `GeneratedAt` en RFC3339 UTC.
   - Ejecuta `json.MarshalIndent(logStructure, "", "  ")` **una sola vez**. Esos bytes exactos (`bytesLog`) se almacenan en `output/log.json` mediante `internal/logstore/store.go: (*FileStore).Save`.
2. **Paso 5 (Hash del log en claro):**
   - Calcula el hash sobre `bytesLog` llamando a `internal/crypto/hasher.go: (*SHA256Hasher).HashHex`.
   - Almacena el hash con salto de línea final (`\n`) en `output/log.sha256` mediante `FileStore.Save`.
3. **Paso 6 (Cifrar log y guardar insumos):**
   - Genera una clave de 256 bits llamando a `internal/crypto/encryptor.go: (*AESGCMEncryptor).GenerateKey`.
   - Guarda la clave en `output/key.bin` con permisos `0600` mediante `FileStore.Save`.
   - Cifra `bytesLog` llamando a `internal/crypto/encryptor.go: (*AESGCMEncryptor).Encrypt(key, bytesLog)`.
   - Guarda el resultado en `output/log.enc` mediante `FileStore.Save`.
4. **Paso 7 (Hash del log cifrado):**
   - Calcula el hash sobre los bytes exactos de `ciphertext` llamando a `SHA256Hasher.HashHex`.
   - Almacena el hash con salto de línea final (`\n`) en `output/log.enc.sha256` mediante `FileStore.Save`.

---

### 7. Parámetros criptográficos reales
Implementado en `internal/crypto/hasher.go` y `internal/crypto/encryptor.go`.

- **Función hash:** SHA-256 (`crypto/sha256`). Salida: cadena hexadecimal en minúsculas de 64 caracteres (`encoding/hex`).
- **Algoritmo de cifrado:** AES-256-GCM (`crypto/aes`, `crypto/cipher`).
- **Tamaño de clave:** 32 bytes (256 bits).
- **Tamaño de nonce:** 12 bytes (96 bits), tamaño estándar de GCM (`gcm.NonceSize()`).
- **Tamaño de tag de autenticación:** 16 bytes (128 bits), overhead estándar de GCM (`gcm.Overhead()`).
- **Origen de la aleatoriedad:** `crypto/rand` (mediante `io.ReadFull(rand.Reader, ...)`).
- **Estructura binaria de `log.enc`:**
  $$\text{log.enc} = \underbrace{\text{nonce}}_{12\text{ bytes}} \;\big\|\; \underbrace{\text{ciphertext}}_{N\text{ bytes}} \;\big\|\; \underbrace{\text{tag}}_{16\text{ bytes}}$$
  Longitud total: $12 + \text{len}(plaintext) + 16 = \text{len}(plaintext) + 28$ bytes.

#### Fragmento de `internal/crypto/encryptor.go: Encrypt`
```go
func (e *AESGCMEncryptor) Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to initialize GCM mode: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: failed to generate cryptographic nonce: %w", err)
	}

	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return sealed, nil
}
```

---

### 8. Tabla de artefactos en `output/`
Constantes definidas en `internal/logstore/store.go`.

| Archivo | Contenido | Permisos (`os.FileMode`) | Paso del Taller |
| :--- | :--- | :---: | :---: |
| `output/log.json` | JSON consolidado de eventos en texto claro | `0644` | Paso 4 |
| `output/log.sha256` | Hash SHA-256 en hexadecimal del log en claro (con `\n`) | `0644` | Paso 5 |
| `output/key.bin` | Clave simétrica cruda de 32 bytes (256 bits) | `0600` | Paso 6 |
| `output/log.enc` | Artefacto cifrado: nonce (12 B) + ciphertext + tag (16 B) | `0644` | Paso 6 |
| `output/log.enc.sha256` | Hash SHA-256 en hexadecimal del log cifrado (con `\n`) | `0644` | Paso 7 |
| `output/log.dec.json` | Bytes descifrados guardados tras verificar la integridad | `0600` | Pasos 8–9 (HU-3) |

---

### 9. Manejo de errores y seguridad en persistencia
- **Errores tipados en `internal/crypto/encryptor.go`:**
  - `ErrInvalidKeySize`: si la clave no tiene exactamente 32 bytes.
  - `ErrCiphertextTooShort`: si la entrada a `Decrypt` es menor a 28 bytes ($12 + 16$).
  - `ErrAuthenticationFailed`: retornado si la verificación del tag GMAC falla o los datos fueron alterados.
- **Errores tipados en `internal/logstore/store.go`:**
  - `ErrInvalidArtifactName`: retornado si el nombre contiene separadores (`/`, `\`), componentes `..` o apunta fuera del directorio base.
- **Errores tipados en `internal/service/protection.go`:**
  - `ErrNoEvents`: si la lista de eventos recibida está vacía.
  - `ErrMissingIDGenerator`: si no se inyectó la función generadora de identificadores UUID.
- **Comportamiento si falla un paso a mitad de `Protect`:**
  - Interrupción inmediata (*fail-fast*) reportando el paso exacto que falló (ej. `paso 6: cifrar log: ...`).
  - Los artefactos ya escritos en disco no se borran para permitir auditoría forense, pero el lote queda inválido. Cualquier ejecución posterior exitosa sobreescribe completamente todos los archivos.
  - La clave simétrica y el texto en claro nunca se imprimen ni se adjuntan en los mensajes de error.

---

## C. Arquitectura

### 10. Paquetes, dependencias e inyección
Estructura según Clean Architecture:

```
cmd/logguard/main.go (Composition Root)
  ├──> internal/cli
  ├──> internal/service
  ├──> internal/generator
  ├──> internal/crypto
  └──> internal/logstore
```

- **Interfaces y sus implementaciones:**
  - `crypto.Hasher` $\leftarrow$ implementada por `crypto.SHA256Hasher`
  - `crypto.Encryptor` $\leftarrow$ implementada por `crypto.AESGCMEncryptor`
  - `generator.EventGenerator` $\leftarrow$ implementada por `generator.RandomEventGenerator`
  - `logstore.ArtifactStore` $\leftarrow$ implementada por `logstore.FileStore`
  - `service.ProtectionService` $\leftarrow$ implementada por `service.protectionService`
  - `service.VerificationService` $\leftarrow$ implementada por `service.verificationService`
- **Regla de dependencias:**
  - `domain` no depende de ningún paquete interno ni externo.
  - `service` depende exclusivamente de interfaces (`Hasher`, `Encryptor`, `ArtifactStore`) y de `domain`. No importa `generator`, `logstore` ni `crypto`.
  - `cli` solo depende de `service`, `generator`, `domain` y de la librería externa `promptui`.
- **Inyección en `cmd/logguard/main.go`:**
  ```go
  gen := generator.NewRandomEventGenerator()
  hasher := crypto.NewSHA256Hasher()
  encryptor := crypto.NewAESGCMEncryptor()
  store := logstore.NewFileStore("./output")
  protectionSvc := service.NewProtectionService(hasher, encryptor, store, service.WithIDFunc(generator.NewUUIDv4))
  verificationSvc := service.NewVerificationService(hasher, encryptor, store)
  presenter := cli.NewPresenter()
  menu := cli.NewMenu(protectionSvc, verificationSvc, presenter, gen)
  ```

---

### 11. Diagramas de arquitectura
Actualizados en `docs/diagrams/structure.mmd` y `docs/diagrams/behavior.mmd`.

- **Diferencias encontradas y corregidas contra el esqueleto inicial:**
  1. `ProtectionService.Protect`: la firma inicial era `Protect(n int)`. Se actualizó a `Protect(events []Event)`.
  2. `service` desacoplado de `generator`: `protectionService` ya no depende de `EventGenerator`, recibe eventos desde `cli.Menu` y el generador de IDs se inyecta desde `main.go`.
  3. `cli.Menu`: ahora almacena `generator` y `Session` para transferir eventos a `ProtectionService`.
  4. `Presenter`: incluye el método `PresentGeneratedEvents(events []Event)`.
  5. Diagrama de secuencia: separa el flujo de HU-1 (pasos 1–3), HU-2 (pasos 4–7) y HU-3 (pasos 8–10).

---

## D. Evidencia real

### 12. Pruebas automatizadas (`go test ./... -count=1`)
Ejecutado con éxito (0 fallos):
```text
?   	github.com/melissa992/Taller_Criptografia_Go/cmd/logguard	[no test files]
ok  	github.com/melissa992/Taller_Criptografia_Go/internal/cli	3.579s
ok  	github.com/melissa992/Taller_Criptografia_Go/internal/crypto	3.281s
ok  	github.com/melissa992/Taller_Criptografia_Go/internal/domain	3.882s
ok  	github.com/melissa992/Taller_Criptografia_Go/internal/generator	3.933s
ok  	github.com/melissa992/Taller_Criptografia_Go/internal/logstore	3.148s
ok  	github.com/melissa992/Taller_Criptografia_Go/internal/service	4.092s
```

- **`internal/cli`:** Validación de rangos numéricos de entrada (valores mínimos, intermedios, máximos, negativos, no enteros y vacíos).
- **`internal/crypto`:** Vectores NIST conocidos de SHA-256; roundtrip de cifrado/descifrado AES-GCM (vacío, texto, 1 MiB); verificación de unicidad de nonces; detección de manipulación en nonce, ciphertext y tag; rechazo de claves inválidas.
- **`internal/domain`:** Determinismo del hash del payload; insensibilidad al campo `payload_hash`; sensibilidad a cambios en campos individuales; roundtrip JSON con verificación; detección de manipulación.
- **`internal/generator`:** Límites de batch y error centinela; reproducibilidad determinista con semilla fija; invariantes de calificaciones por tipo de evento; distribución estadística uniforme; validación de UIDs y UUIDs v4.
- **`internal/logstore`:** Roundtrip de lectura/escritura en disco; creación de directorios automáticos; rechazo estricto de secuencias de path traversal (`..`, `/`, `\`); manejo de archivos inexistentes.
- **`internal/service`:** Verificación con fakes de la generación de los 5 artefactos; validación de bytes idénticos entre serialización, hash y cifrado; propagación de errores por paso; prueba de integración real de extremo a extremo.

---

### 13. Salida del CLI (Menú interactivo con n=10)
Debido a que el menú interactivo con `promptui` requiere una consola interactiva (TTY) con soporte de flechas y retorna EOF en subprocesos no interactivos, se proporciona el comando para su ejecución:

```powershell
go run ./cmd/logguard
```

> **PENDIENTE: pegar salida real** de la ejecución interactiva en PowerShell para el informe final.

---

### 14. Comandos de verificación independiente en PowerShell

Tras ejecutar las opciones 1 y 2 en el CLI, los siguientes comandos verifican los artefactos:

#### 1. Verificación del hash de `log.json` frente a `log.sha256`
```powershell
$calc = (Get-FileHash output/log.json -Algorithm SHA256).Hash.ToLower()
$saved = (Get-Content output/log.sha256).Trim().ToLower()
Write-Host "Calculado: $calc`nGuardado:   $saved`nCoinciden:  $($calc -eq $saved)"
```
- **Resultado esperado:** `Coinciden: True`

#### 2. Verificación del hash de `log.enc` frente a `log.enc.sha256`
```powershell
$calcEnc = (Get-FileHash output/log.enc -Algorithm SHA256).Hash.ToLower()
$savedEnc = (Get-Content output/log.enc.sha256).Trim().ToLower()
Write-Host "Calculado: $calcEnc`nGuardado:   $savedEnc`nCoinciden:  $($calcEnc -eq $savedEnc)"
```
- **Resultado esperado:** `Coinciden: True`

#### 3. Tamaño exacto de la clave simétrica `key.bin`
```powershell
(Get-Item output/key.bin).Length
```
- **Resultado esperado:** `32` (bytes correspondientes a 256 bits).

#### 4. Diferencia exacta de tamaño entre `log.enc` y `log.json`
```powershell
$diff = (Get-Item output/log.enc).Length - (Get-Item output/log.json).Length
Write-Host "Diferencia de tamaño: $diff bytes (Esperado: 28 = 12 nonce + 16 tag)"
```
- **Resultado esperado:** `Diferencia de tamaño: 28 bytes`

#### 5. Ausencia de texto en claro en el archivo cifrado
```powershell
$raw = Get-Content output/log.enc -Raw
Write-Host "Contiene 'GRADE_': $($raw -match 'GRADE_')"
Write-Host "Contiene 'student_uid': $($raw -match 'student_uid')"
```
- **Resultado esperado:** Ambas comprobaciones devuelven `False`.

---

## E. Material para la sustentación

### 15. Decisiones de diseño y justificación
- **SHA-256:** Estándar FIPS con seguridad de preimagen y colisiones de 128 bits frente a ataques de cumpleaños.
- **AES-256-GCM vs CBC y ECB:** Modo AEAD que proporciona confidencialidad y autenticación de integridad en una sola operación. CBC carece de integridad nativa y es vulnerable a ataques de *padding oracle*; ECB no oculta patrones de bloques.
- **Hash individual vs Hash global:** El hash por registro permite verificar individualmente cada evento y detectar adulteraciones puntuales; el hash global asegura la integridad y el orden de la colección completa.
- **Nonce único por operación:** La reutilización del nonce en GCM destruye la autenticidad al permitir la recuperación de la subclave de autenticación GHASH.
- **`crypto/rand` vs `math/rand`:** `crypto/rand` aprovecha la entropía del kernel del SO para claves, nonces y UUIDs. `math/rand/v2` se restringe a datos simulados para no comprometer material criptográfico.
- **`promptui` como única dependencia externa:** Limita la superficie de ataque de dependencias de terceros; el núcleo de seguridad utiliza exclusivamente la biblioteca estándar de Go.

---

### 16. Limitaciones conocidas
- **Permisos en Windows:** `os.WriteFile` con modo `0600` no restringe las listas de control de acceso (ACLs) de Windows como lo hace en sistemas POSIX.
- **Almacenamiento de clave en disco:** En un entorno productivo de grado corporativo, la clave simétrica no debe almacenarse en el mismo sistema de archivos que los datos cifrados; debe custodiarse en un KMS (AWS KMS, Vault) o un HSM FIPS 140-2.
- **Fallas intermedias:** Ante un error durante el pipeline de protección, los artefactos ya creados no se borran para facilitar auditorías forenses, pero el lote queda catalogado como incompleto.
- **Referencia de integridad:** La verificación compara los bytes descifrados con el hash almacenado en `log.sha256`. Un `log.dec.json` anterior puede seguir en disco si la verificación falla.

---

### 17. Checklist de demostración en vivo

#### (a) Demostración HU-1
1. Ejecutar `go run ./cmd/logguard`.
2. Probar entradas inválidas en opción 1:
   - Cadena vacía $\rightarrow$ Error visible: *"la cantidad no puede estar vacía"*.
   - Texto `"abc"` $\rightarrow$ Error visible: *"debe ingresar un número entero válido"*.
   - Cero `0` $\rightarrow$ Error visible: *"la cantidad de eventos debe ser al menos 1"*.
   - Número `10001` $\rightarrow$ Error visible: *"la cantidad de eventos no puede superar 10000"*.
3. Ingresar cantidad válida `10`:
   - Verificar la tabla resumen con conteo equilibrado de `GRADE_REGISTERED` y `GRADE_MODIFIED`.
   - Verificar que las notas están en $[0.0, 5.0]$, UIDs formateados y hash de 12 caracteres visibles.

#### (b) Demostración HU-2
1. Sin haber generado eventos, seleccionar opción 2:
   - Verificar aviso amigable: *"[AVISO] Primero debes generar eventos de log (opción 1)"* sin salida abrupta del programa.
2. Tras generar eventos, seleccionar opción 2:
   - Verificar que se muestra el `log_id`, conteos, hashes en hexadecimal completo (64 caracteres) y la lista de 5 artefactos generados.
3. En una consola paralela de PowerShell, ejecutar los comandos de verificación independiente:
   - Coincidencia de hashes `log.sha256` y `log.enc.sha256`.
   - Longitud de `key.bin` = 32 bytes.
   - Longitud `log.enc` = `log.json` + 28 bytes.
   - Ausencia de texto claro en `log.enc`.

---

### 18. Banco de preguntas y respuestas para sustentación
1. **¿Por qué no se usó AES-ECB para cifrar el archivo JSON?**
   AES-ECB cifra cada bloque de 16 bytes de manera idéntica e independiente. En estructuras repetitivas como JSON, preserva patrones y filtra información estructural sobre los campos y valores cifrados.
2. **¿Qué consecuencia crítica ocurre si se reutiliza un nonce con la misma clave en AES-GCM?**
   En AES-GCM, repetir el nonce con la misma clave permite a un atacante recuperar la subclave GHASH y forjar etiquetas de autenticación para cualquier mensaje, además de revelar la operación XOR entre los textos en claro.
3. **¿Por qué se calcula un hash antes de cifrar y otro después de cifrar?**
   El hash del log en claro (`log.sha256`) garantiza la integridad semántica del contenido una vez recuperado, mientras que el hash del cifrado (`log.enc.sha256`) permite validar la integridad física del archivo cifrado en reposo sin necesidad de descifrarlo previamente.
4. **¿Por qué se excluye el campo `payload_hash` en el cálculo de su propio hash?**
   Si el campo formara parte del mensaje de entrada del digest, el resultado alteraría el contenido del evento, generando un ciclo de cálculo infinito sin solución estática.
5. **¿Por qué se implementó una `struct` privada para el payload en lugar de usar un `map`?**
   Go no garantiza el orden de iteración de claves en los mapas, mientras que la serialización JSON de una `struct` respeta rígidamente el orden de declaración de los campos, asegurando un digest criptográfico determinista.
6. **¿Por qué los campos de calificación son punteros `*float64`?**
   En Go, el tag `omitempty` excluye el *zero value* del tipo primitivo. Un float primitivo con valor `0.0` desaparecería del JSON; mediante punteros, solo se omite si su referencia es `nil`.
7. **¿Por qué se utilizó `float64(rng.IntN(51)) / 10.0` para las notas simuladas?**
   Porque redondear un número continuo asigna a los extremos 0.0 y 5.0 intervalos de ancho 0.05 (mitad de probabilidad), mientras que los valores interiores tienen un ancho de 0.10. Muestrear sobre 51 enteros discretos asigna a cada nota exactamente un $1/51$ de probabilidad.
8. **¿Cómo se protege el sistema contra ataques de Path Traversal al guardar artefactos?**
   `FileStore.validateName` verifica que el nombre no contenga separadores de ruta (`/`, `\`), caracteres `..`, y que coincida estrictamente con su elemento base, evitando escrituras fuera del directorio base configurado.
9. **¿Por qué se utiliza `crypto/subtle.ConstantTimeCompare` al validar hashes?**
   Una comparación estándar de cadenas con `==` termina en el primer byte desigual, filtrando información del tiempo de ejecución que un atacante puede explotar en un ataque de canal lateral. La comparación en tiempo constante neutraliza este vector.
10. **¿Cómo se desacopló la capa de servicio de la infraestructura criptográfica y de almacenamiento?**
    `ProtectionService` depende exclusivamente de interfaces (`Hasher`, `Encryptor`, `ArtifactStore`) inyectadas por constructor en `main.go`. Esto permite sustituir implementaciones o usar mocks para pruebas unitarias sin alterar la lógica de negocio.

---

### 19. Glosario de cifras para diapositivas
- **32 bytes (256 bits):** Tamaño de la clave simétrica AES-256 (`key.bin`).
- **12 bytes (96 bits):** Tamaño del nonce criptográfico de AES-GCM.
- **16 bytes (128 bits):** Tamaño de la etiqueta de autenticación GMAC de AES-GCM.
- **28 bytes:** Sobrecarga de longitud de `log.enc` respecto a `log.json` (12 nonce + 16 tag).
- **64 caracteres:** Longitud de los hashes hexadecimales de SHA-256 (`log.sha256`, `log.enc.sha256`, `payload_hash`).
- **5 artefactos:** Archivos producidos en `output/` por HU-2 (`log.json`, `log.sha256`, `key.bin`, `log.enc`, `log.enc.sha256`).
- **51 valores discretos:** Cantidad de notas posibles en el intervalo uniforme $[0.0, 5.0]$ con saltos de $0.1$.
- **10000 eventos:** Límite máximo configurable por lote (`generator.MaxEvents`).
- **Número de pruebas unitarias por paquete:**
  - `internal/cli`: 1 suite table-driven (15 sub-tests de validación).
  - `internal/crypto`: 6 tests unitarios (incluyendo pruebas con 1 MiB de datos y vectores NIST).
  - `internal/domain`: 6 tests unitarios (determinismo, roundtrip y detección de manipulación).
  - `internal/generator`: 5 tests unitarios (reproducibilidad, invariantes y verificación masiva de 5000 eventos).
  - `internal/logstore`: 3 tests unitarios (roundtrip, 16 sub-tests de path traversal y archivos faltantes).
  - `internal/service`: 5 tests unitarios e integraciones reales de extremo a extremo.

---

## F. Verificación de integridad (HU-3)

### 20. Flujo implementado para la HU-3
1. **Paso 8:** La opción «Verificar log guardado» coteja el hash de `log.enc` con `log.enc.sha256`, autentica y descifra el contenido con AES-256-GCM y reconstruye el log JSON.
2. **Paso 9:** Calcula SHA-256 sobre los bytes recuperados y compara el resultado en tiempo constante con `output/log.sha256`. Si coinciden, guarda esos bytes en `output/log.dec.json`.
3. **Paso 10:** Presenta el total y los tipos de eventos, los hashes de las tres etapas y el veredicto de integridad.
4. **Comprobación de alteraciones:** Las pruebas verifican que un cifrado alterado se detecte tanto mediante el hash almacenado como mediante la autenticación GCM. La CLI ofrece la verificación del log guardado.

