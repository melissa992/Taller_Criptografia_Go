# Reglas de Contexto Persistente — LogGuard

Este documento consolida las restricciones inmutables y directrices de implementación para el desarrollo de las siguientes Historias de Usuario (HU-1, HU-2, HU-3).

---

## 1. Restricciones Técnicas y Dependencias
- **Lenguaje**: Go 1.22+.
- **Módulo**: `github.com/melissa992/Taller_Criptografia_Go` (reemplazable por el username de GitHub).
- **Primitivas criptográficas**: Estrictamente biblioteca estándar de Go:
  - `crypto/sha256`
  - `crypto/aes`
  - `crypto/cipher`
  - `crypto/rand`
  - `crypto/subtle` (para comparación segura de hashes en tiempo constante: `subtle.ConstantTimeCompare`).
- **Librerías externas**: Únicamente `github.com/manifoldco/promptui` para el menú CLI interactivo (solo importable desde `internal/cli`).
- **Generación de UUIDs**: Generador propio v4 usando `crypto/rand` (sin dependencias como google/uuid).
- **Aleatoriedad**:
  - `crypto/rand`: Llaves, nonces y UUIDs.
  - `math/rand/v2`: Simulación de notas académicas [0.0, 5.0], roles simulados, UIDs de curso/estudiante.

---

## 2. Flujo Funcional (10 Pasos)
1. **Entrada**: Solicitar al usuario cantidad de eventos a simular ($n \ge 1$).
2. **Generación**: Producir eventos de tipo `GRADE_REGISTERED` o `GRADE_MODIFIED`, con notas uniformes en $[0.0, 5.0]$.
3. **Hash de Evento**: Calcular SHA-256 del payload serializado (omitiendo explícitamente `payload_hash` para evitar circularidad).
4. **Consolidación**: Crear `Log` estructurado con metadatos (`log_id`, `version`, `generated_at`, `event_count`, `events`).
5. **Hash del Log en Claro**: Generar `log.sha256` a partir de los bytes exactos de `log.json` (sin re-serializar).
6. **Cifrado**: Generar clave AES-256 aleatoria (guardar en `key.bin` con permisos `0600`). Cifrar `log.json` con AES-256-GCM y nonce de 12 bytes (`nonce || ciphertext || tag`) en `log.enc`.
7. **Hash del Cifrado**: Generar SHA-256 de `log.enc` y guardarlo en `log.enc.sha256`.
8. **Descifrado**: Cotejar `log.enc` con `log.enc.sha256`, autenticar y descifrar con AES-256-GCM y `key.bin`, y reconstruir el log en memoria.
9. **Hash del Descifrado**: Calcular SHA-256 de los bytes recuperados y comparar en tiempo constante con `log.sha256`. Guardar esos bytes en `log.dec.json` si los hashes coinciden.
10. **Reporte**: Presentar en consola el resumen de eventos por tipo, hashes en cada etapa y veredicto booleano de integridad.

---

## 3. Principios de Código y Manejo de Errores
- **Cero Pánicos**: No usar `panic` en ningún paquete. Todos los errores deben propagarse usando contexto estructurado:
  ```go
  fmt.Errorf("contexto de la falla: %w", err)
  ```
- **Privacidad**: No utilizar datos personales reales (PII). Utilizar UIDs anónimos (`est-XXXX`, `prof-YYYY`, `mat-ZZZZ`).
- **Inmutabilidad de Bytes**: El hash del log en texto claro y el cifrado deben operar sobre el mismo slice `[]byte` exacto que se escribe a disco en `output/log.json`.
- **Arquitectura**: Mantener el desacoplamiento estricto: `domain` sin dependencias, `service` dependiente únicamente de interfaces.

---

## 4. HU-1 completada

### Decisiones de Implementación Tomadas
1. **Discretización uniforme de notas**: Muestreo uniforme sobre 51 puntos discretos $\{0.0, 0.1, \dots, 5.0\}$ mediante `float64(rng.IntN(51)) / 10.0`. Se descartó redondear números flotantes continuos porque los extremos (0.0 y 5.0) tendrían intervalos de ancho 0.05 (mitad de probabilidad relativa respecto a los valores interiores con ancho 0.1).
2. **Pool de UIDs simulados**: Por cada lote se instancian 5 docentes (`doc-XXXXXX`), 20 estudiantes (`est-XXXXXX`) y 5 cursos (`cur-XXXXXX`) generados con el generador pseudoaleatorio, permitiendo repeticiones realistas de actores y asignaturas.
3. **Prevención de circularidad de hash (`eventPayload`)**: La estructura privada `eventPayload` replica exactamente los campos y tags JSON de `Event` omitiendo de forma estricta `payload_hash`. Se utiliza una struct (y no un map) para garantizar ordenamiento determinista de claves durante `json.Marshal`.
4. **Verificación en tiempo constante**: `domain.VerifyPayloadHash` utiliza `crypto/subtle.ConstantTimeCompare` para prevenir ataques de canal lateral basados en tiempo.
5. **Generador UUID v4 nativo**: Implementado en `internal/generator/uuid.go` usando exclusivamente `crypto/rand` con configuración canónica de bits de versión (4) y variante RFC 4122 (`10xx`).

### Firmas Públicas Disponibles para HU-2
- **`domain`**:
  - `domain.ComputePayloadHash(e Event) (string, error)`: Calcula el hash SHA-256 en hexadecimal (64 caracteres) del evento excluyendo su propio hash.
  - `domain.VerifyPayloadHash(e Event) (bool, error)`: Verifica la integridad de un evento recalculando el digest y comparando en tiempo constante.
  - `domain.Event`, `domain.EventType`, `domain.GradeRegistered`, `domain.GradeModified`.
  - `domain.Log`: Estructura para consolidación de logs (`LogID`, `Version`, `GeneratedAt`, `EventCount`, `Events`).
- **`generator`**:
  - `generator.MaxEvents`: Constante de límite máximo (`10000`).
  - `generator.ErrInvalidEventCount`: Error centinela para validación de rango $[1, 10000]$.
  - `generator.EventGenerator`: Interfaz de generación `Generate(n int) ([]domain.Event, error)`.
  - `generator.NewRandomEventGenerator(opts ...Option) *RandomEventGenerator`: Constructor con opciones funcionales (`WithSeed`, `WithClock`, `WithIDFunc`).
- **`cli`**:
  - `cli.Session`: Estructura en memoria con campo `Events []domain.Event` donde quedan almacenados los eventos para que HU-2 los tome al consolidar.
  - `cli.ValidateEventCount(input string) error`: Validador puro de cadenas numéricas para captura de CLI.

---

## 5. HU-2 completada

### Decisiones de Implementación Tomadas
1. **Cambio autorizado en firma de `Protect`**: Modificada de `Protect(n int)` a `Protect(events []domain.Event) (ProtectionResult, error)`. Esto permite consolidar y proteger exactamente la colección de eventos generada y validada en pantalla durante la HU-1 (`Session.Events`), evitando discrepancias por regeneración pseudoaleatoria.
2. **Formato estándar del artefacto cifrado**: `log.enc` se estructura estrictamente como `nonce (12 bytes) || ciphertext || tag (16 bytes)`. Cada operación genera un nonce fresco mediante `crypto/rand`, previniendo catastróficos ataques de reutilización de nonce en GCM.
3. **Inmutabilidad y unicidad de serialización**: `domain.Log` se serializa con `json.MarshalIndent` una sola vez. Esos bytes exactos son los que se escriben a `output/log.json`, se alimentan a `HashHex` para `log.sha256` y se pasan a `Encrypt` para producir `log.enc`.
4. **Semántica de fallas (*Fail-Fast*)**: Si cualquier paso intermedio falla, se interrumpe el flujo retornando un error contextualizado (ej. `"paso 6: cifrar log: ..."`). Los artefactos parciales se conservan para fines forenses/depuración pero se consideran inválidos; cualquier corrida exitosa posterior sobreescribe completamente todos los artefactos.
5. **Generador de UUID desacoplado**: `generator.NewUUIDv4` es la implementación canónica exportada de UUID v4 con entropía criptográfica (`crypto/rand`). `service` no importa `generator`, sino que recibe esta función por inyección mediante la opción funcional `service.WithIDFunc`.

### Constantes y Firmas Públicas Disponibles para HU-3
- **`logstore`**:
  - `logstore.LogFile = "log.json"`
  - `logstore.LogHashFile = "log.sha256"`
  - `logstore.KeyFile = "key.bin"`
  - `logstore.EncryptedLogFile = "log.enc"`
  - `logstore.EncryptedHashFile = "log.enc.sha256"`
  - `logstore.DecryptedLogFile = "log.dec.json"`
  - `logstore.ArtifactStore`: Interfaz con métodos `Save(name string, data []byte, perm os.FileMode) error` y `Load(name string) ([]byte, error)`.
  - `logstore.ErrInvalidArtifactName`: Error de protección contra path traversal.
- **`crypto`**:
  - `crypto.Encryptor`: Interfaz completa que incluye `Decrypt(key, data []byte) ([]byte, error)`.
  - `crypto.Hasher`: Interfaz con `HashHex(data []byte) string`.
  - `crypto.ErrAuthenticationFailed`: Error centinela retornado ante fallos de integridad o alteración en `Decrypt`.
  - `crypto.ErrInvalidKeySize` y `crypto.ErrCiphertextTooShort`.
- **`service`**:
  - `service.ProtectionResult`: Estructura con `LogID`, `EventCount`, `EventsByType`, `PlainLogHash`, `EncryptedLogHash`, `ArtifactFiles`.
  - `service.VerificationService`: Verifica los artefactos persistidos y devuelve un reporte de integridad (`Verify() (domain.Report, error)`).



