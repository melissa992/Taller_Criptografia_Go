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
8. **Descifrado**: Leer `key.bin` y `log.enc`, descifrar con AES-256-GCM y guardar en `log.dec.json`.
9. **Hash del Descifrado**: Calcular SHA-256 de `log.dec.json` y comparar en tiempo constante con `log.sha256`.
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

