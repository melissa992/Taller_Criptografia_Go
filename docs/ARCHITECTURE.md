# Arquitectura del Sistema LogGuard

## 1. Visión General y Propósito
**LogGuard** es una herramienta de línea de comandos (CLI) desarrollada en Go que implementa el ciclo de vida de **protección de logs estructurados en reposo** para eventos académicos (registro y modificación de calificaciones). El sistema garantiza la **confidencialidad**, **integridad** y **verificabilidad** de los registros mediante primitivas criptográficas robustas y un diseño de arquitectura limpia desacoplada.

---

## 2. Decisiones Criptográficas y Transversales

### 2.1 Función de Hashing: SHA-256
- **Elección**: SHA-256 (estándar FIPS 180-4, vía `crypto/sha256` de Go stdlib).
- **Justificación**: Proporciona una resistencia comprobada frente a preimagen y colisiones (seguridad de 128 bits frente a ataques de cumpleaños). Se descartan funciones obsoletas como MD5 y SHA-1 debido a vulnerabilidades prácticas conocidas de colisión.
- **Uso**: 
  1. Hashing individual de payload de cada evento para integridad granular.
  2. Hashing del archivo de log consolidado en texto plano (`log.sha256`).
  3. Hashing del archivo de log cifrado (`log.enc.sha256`).
  4. Hashing de verificación posterior al descifrado para constatar la fidelidad del contenido restaurado.

### 2.2 Algoritmo de Cifrado Simétrico: AES-256-GCM vs CBC / ECB
- **Elección**: **AES-256-GCM** (Galois/Counter Mode con llave de 256 bits, vía `crypto/aes` y `crypto/cipher`).
- **Justificación**:
  - **Autenticación Integrada (AEAD)**: Proporciona simultáneamente confidencialidad y autenticación de integridad mediante una etiqueta de autenticación (GMAC / Tag de 128 bits). Si el texto cifrado o el nonce son manipulados en disco, la operación de descifrado falla inmediatamente sin revelar texto en claro.
  - **Inmunidad a Padding Oracle**: Al ser un cifrador de flujo derivado de un contador, no requiere relleno PKCS#7, eliminando ataques clásicos como *padding oracle* o *BEAST* presentes en AES-CBC si no se implementa un esquema estricto de Encrypt-then-MAC con HMAC.
  - **Inseguridad crítica de ECB**: AES-ECB fue totalmente descartado porque no oculta patrones en los bloques de datos idénticos (filtrando la estructura del JSON).
- **Manejo del Nonce**:
  - Se genera un nonce aleatorio único de **12 bytes (96 bits)** por cada operación de cifrado utilizando `crypto/rand`.
  - El formato de almacenamiento del artefacto cifrado sigue el estándar `nonce (12 bytes) || ciphertext || auth_tag (16 bytes)`. El nonce se almacena como prefijo público del archivo cifrado.
  - **Regla crítica**: La reutilización de un nonce con la misma clave AES-GCM anula la seguridad del esquema (permite recuperar la clave GHASH y forjar mensajes). Por ello, cada invocación a `Encrypt` extrae 12 bytes frescos de entropía del sistema operativo.

### 2.3 Generación de Aleatoriedad: `crypto/rand` vs `math/rand/v2`
- **Material Criptográfico (`crypto/rand`)**:
  - Claves simétricas (32 bytes para AES-256).
  - Nonces (12 bytes para GCM).
  - Identificadores únicos universales (UUID v4) generados mediante entropía criptográfica directa del sistema operativo.
- **Datos Simulados (`math/rand/v2`)**:
  - Generación de calificaciones numéricas dentro del intervalo uniforme $[0.0, 5.0]$.
  - Asignación de tipos de eventos (`GRADE_REGISTERED`, `GRADE_MODIFIED`).
  - Generación de identificadores simulados de estudiantes y cursos.
  - **Regla estricta**: Ningún valor emitido por `math/rand/v2` se utiliza directa o indirectamente como semilla, clave, vector o nonce criptográfico.

### 2.4 Gestión de Llaves: Entorno Académico vs Producción (KMS / HSM)
- **Implementación actual (Taller)**: La llave de 256 bits se almacena localmente en el archivo `output/key.bin` con permisos de sistema de archivos restrictivos (`0600` – lectura/escritura exclusiva para el usuario propietario).
- **Limitación en Sistemas Windows**:
  > [!NOTE]
  > En sistemas operativos Windows, `os.WriteFile` con modo `0600` no restringe los descriptores de seguridad (ACLs) de la misma forma que en sistemas POSIX, heredando permisos del directorio contenedor. No se implementan llamadas específicas a APIs de Windows (como Win32 SetSecurityInfo) para mantener portabilidad limpia; en su lugar, se asume la limitación inherente del entorno local de desarrollo.
- **Consideración de Producción**:
  > [!IMPORTANT]
  > En un entorno productivo real, almacenar claves criptográficas en el mismo sistema de almacenamiento que los datos en reposo anula la defensa en profundidad. Una arquitectura de grado corporativo debe delegar la custodia y uso de claves a un servicio de administración de claves (**KMS** como AWS KMS, Google Cloud KMS, HashiCorp Vault) o a módulos de seguridad de hardware (**HSM** bajo norma FIPS 140-2/3 Level 3+), utilizando técnicas de *Envelope Encryption* (DEK protegida por KEK maestra que nunca abandona el hardware de seguridad).

---

## 3. Esquema del Log y Prevención de Circularidad

### 3.1 Esquema JSON del Log
El archivo `log.json` consolida una colección estructurada de eventos:

```json
{
  "log_id": "c1f7b822-4412-4c28-98e3-469bfd08b3c1",
  "version": "1.0",
  "generated_at": "2026-11-06T00:00:00Z",
  "event_count": 2,
  "events": [
    {
      "event_id": "78a9c211-e734-4a25-a1c2-637dc67b2099",
      "event_type": "GRADE_REGISTERED",
      "timestamp": "2026-11-06T00:00:00Z",
      "actor_uid": "prof-001",
      "student_uid": "est-4521",
      "course_uid": "mat-101",
      "grade": 4.5,
      "payload_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  ]
}
```

### 3.2 Prevención de Circularidad en el Hash del Payload
- **Problema de Circularidad**: Si el cálculo del hash de un evento incluye el campo `payload_hash`, el valor del hash cambiaría a sí mismo indefinidamente.
- **Solución Arquitectónica**:
  - La función `ComputePayloadHash(e Event)` proyecta los datos del evento a una representación canónica o sub-estructura que **omite estrictamente** el campo `payload_hash`.
  - La serialización de los atributos del payload (`event_id`, `event_type`, `timestamp`, `actor_uid`, `student_uid`, `course_uid`, calificaciones) sigue un orden determinista y formatos de fecha normalizados (RFC3339).

### 3.3 Regla de Inmutabilidad del Log en Claro
> [!NOTE]
> Los bytes serializados exactos generados para `log.json` son pasados directamente a la función de digest `HashHex(bytes)` y al cifrador `Encrypt(key, bytes)`. Bajo ninguna circunstancia el log se des-serializa y re-serializa entre el cálculo del hash y el cifrado, garantizando que variaciones en espacios en blanco o el ordenamiento de claves JSON no invaliden los hashes.

---

## 4. Artefactos Producidos en `output/`

El pipeline genera los siguientes artefactos en el directorio `output/`:
- `log.json`: Documento JSON del log en texto claro.
- `log.sha256`: Hash SHA-256 en hexadecimal del contenido exacto de `log.json`.
- `key.bin`: Clave simétrica cruda de 32 bytes (permisos `0600`).
- `log.enc`: Archivo binario con la estructura `nonce (12 B) || ciphertext || tag (16 B)`.
- `log.enc.sha256`: Hash SHA-256 en hexadecimal del contenido de `log.enc`.
- `log.dec.json`: Resultado del descifrado de `log.enc` mediante `key.bin`, utilizado para verificar la igualdad con el hash original.

### 4.1 Semántica de Falla y Estado de Artefactos
Si la ejecución de `Protect` falla en un paso intermedio (por ejemplo, fallo de I/O al escribir `key.bin` o error de cifrado):
- **Comportamiento adoptado**: *Fail-fast* con reporte de contexto del paso fallido (ej. `"paso 6: cifrar log: ..."`).
- **Tratamiento de artefactos parciales**: No se eliminan los artefactos que hayan alcanzado a escribirse en disco. Esto permite inspección forense y depuración del estado del sistema en auditorías. Sin embargo, el conjunto queda catalogado como inválido e incompleto ya que la cadena de hashes y cifrado no se cerró.
- **Sobreescritura garantizada**: Cualquier ejecución posterior exitosa sobreescribe completamente todos los archivos en `output/` con una clave, un nonce y un lote de hashes nuevos.

---

## 5. Reglas de Dependencias y Arquitectura en Capas

El proyecto implementa los principios de **Clean Architecture**:
1. **`internal/domain`**: Capa central pura. Define entidades (`Event`, `Log`, `Report`) e identificadores de tipo. No contiene I/O, no depende de ningún otro paquete ni de librerías externas.
2. **`internal/crypto`** y **`internal/generator`**: Implementaciones técnicas aisladas. Sólo importan `domain` cuando es estrictamente necesario.
3. **`internal/logstore`**: Capa de persistencia. Expone la abstracción `ArtifactStore` y no conoce a `service` ni a `cli`.
4. **`internal/service`**: Capa de casos de uso y orquestación. Depende exclusivamente de **interfaces** (`Hasher`, `Encryptor`, `ArtifactStore`). Desacoplado de implementaciones concretas y sin dependencia hacia `generator`.
5. **`internal/cli`**: Capa de presentación. Único paquete autorizado a importar `promptui`. No contiene lógica criptográfica ni de negocio.
6. **`cmd/logguard/main.go`**: Composition root. Instancia las dependencias concretas y las inyecta en los constructores de los servicios y controladores.
