# Agilidad criptográfica, paso 1. Auditoría Ed25519

Auditoría de solo lectura sobre `main` `27ceddbbd295162ca351ea5dfa47fe8bb37315a3`.
El tag anotado `v0.3.6` en origin (`89d9120b63f2b6becf8bb4ad7af7bf8bb7d1e92b`)
descuelga en ese commit (`git ls-remote --tags origin`). El clon local no
tenía el tag. No hay cambio de código en este documento.

Alcance: firma y verificación de recibos, aprobaciones y atestaciones.
Entran también la autoridad, el intent y la rotación de clave, porque el
recibo los verifica, y la ingesta y el manifiesto de safety, porque usan el
mismo primitivo. Cada sitio se clasifica así:

- **acoplado**: el archivo nombra `ed25519_dalek` (`SigningKey`,
  `VerifyingKey`, `Signature`) o llama `verify_strict` sobre ese tipo.
- **abstracción parcial**: el archivo no nombra `ed25519_dalek` y pasa por
  `VerifiedPublicKey`, `AgentKeyPair`, `EvidenceAttesterKey`,
  `ExecutionAttestationSigner` o `HumanApprovalVerifier`. El contrato sigue
  siendo Ed25519: 32 bytes de clave, 64 de firma, `verify_strict` y el
  literal `"ed25519"` viven detrás de esa API.

No hay especificación TLA+ en el árbol (`*.tla` ausente, sin invariantes
nombrados). La propuesta de invariante está marcada como propuesta.

## Primitivo único, tres copias

La verificación estricta vive en un solo método y se repite al lado.

| Sitio | Qué hace | Clase |
|---|---|---|
| `crates/praetore-core/src/identity.rs:188` | `VerifiedPublicKey(VerifyingKey)` | acoplado |
| `identity.rs:191-201` | `from_bytes` exige `[u8; 32]` y rechaza `is_weak()` | acoplado |
| `identity.rs:204` | `as_bytes` devuelve `[u8; 32]` | acoplado |
| `identity.rs:212-226` | `Signature::from_slice` y `verify_strict` | acoplado, primitivo |
| `crates/praetore-core/src/evidence.rs:450-459` | otra vez `Signature::from_slice` y `verify_strict` sobre `as_verifying_key()` | acoplado, copia |
| `crates/praetore-core/src/key_rotation.rs:112-120` | tercera copia de `Signature::from_slice` y `verify_strict` | acoplado, copia |

`identity.rs:212` es la abstracción que el resto debería usar. Recibos de
evidencia y pruebas de rotación no pasan por ella.

Firma con `SigningKey` en el núcleo:

| Sitio | Qué hace | Clase |
|---|---|---|
| `evidence.rs:68-97` | `EvidenceAttesterKey` guarda `SigningKey`. `generate` usa `OsRng` | acoplado |
| `evidence.rs:95-98` | `from_secret_bytes(secret: &[u8; 32])` y `SigningKey::from_bytes` | acoplado |
| `evidence.rs:111-116` | `sign_with_domain` devuelve `[u8; 64]` | acoplado |
| `evidence.rs:408-427` | `sign_unchecked` pone `attester_algorithm = "ed25519"` y firma con `signing_key.sign` | acoplado |
| `evidence.rs:430-436` | `verify_attester_signature` exige el literal `"ed25519"` | acoplado |
| `evidence.rs:492-495` | `from_json` de un recibo v2 exige `"ed25519"` | acoplado |
| `evidence.rs:587-602` | cota: la firma hex no puede pasar de 128 caracteres. Si hay algoritmo, tiene que ser `"ed25519"`. No exige longitud 128 | acoplado |
| `identity.rs:144-184` | `AgentKeyPair` guarda `SigningKey`, `generate` con `OsRng`, `from_secret_bytes(&[u8; 32])`, `sign_domain_message` | acoplado |
| `identity.rs:109-114` | `verified_public_key` rechaza todo algoritmo distinto de `"ed25519"` | acoplado |
| `identity.rs:175` | el identity serializado escribe `key_algorithm: "ed25519"` | acoplado |

Quien verifica sin nombrar dalek (abstracción parcial), siempre vía
`VerifiedPublicKey::verify_domain_message`:

| Sitio | Objeto |
|---|---|
| `crates/praetore-core/src/authority.rs:205-215` | firma de autoridad, `AgentKeyPair::sign_domain_message` |
| `authority.rs:235-251` | `Authority::verify_signature` |
| `crates/praetore-core/src/authorization.rs:224-236` | `sign_intent` |
| `authorization.rs:240-266` | `sign_intent_v2` |
| `authorization.rs:269-288` | `verify_intent_signature` |
| `crates/praetore-core/src/storage_record.rs:74-84` | `StorageRecordSigner` implementado por `EvidenceAttesterKey` |
| `storage_record.rs:195-220` | `StorageRecord::verify`. Exige `is_canonical_signature_hex` (128 hex) |
| `crates/praetore-core/src/safety_ingest.rs:548-563` | `SafetyEvent::verify` |
| `safety_ingest.rs:1274-1289` | `SafetyRecord::verify` |
| `crates/praetore-core/src/safety_namespace.rs:699-710` | `SafetyNamespaceManifest::verify` |
| `crates/praetore-receipt/src/lib.rs:522-558` | `ExecutionAttestation::verify` |
| `crates/praetore-receipt/src/approval.rs:135-153` | `HumanApprovalDecision::verify_signature` |
| `approval.rs:344-366` | cierre `approval_expired`, con `signature.len() != 64` antes del primitivo |
| `crates/praetore-mcp/src/approvals.rs:952-970` | `check_signature` de la aprobación local |
| `crates/praetore-gateway/src/lib.rs:206-259` | `HumanApprovalVerifier::verify` delega en `verify_signature` |

`praetore-gateway` (el crate de biblioteca) no importa `ed25519_dalek`.
La dependencia está en `[dev-dependencies]` (`crates/praetore-gateway/Cargo.toml:35`).
`praetore-receipt` igual (`Cargo.toml:29`, dev). `praetore-replay-postgres`
igual (`Cargo.toml:30`, dev).

## Acoplado fuera del núcleo

Estos binarios firman con `SigningKey` en código de producción. No pasan
por `AgentKeyPair` ni por `EvidenceAttesterKey`.

| Sitio | Rol | Clase |
|---|---|---|
| `crates/praetore-mcp/src/approvals.rs:13` | `use ed25519_dalek::{Signer, SigningKey}` | acoplado |
| `approvals.rs:933-950` | `sign` toma `[u8; 32]`, devuelve `[u8; 64]`, hex de la firma | acoplado |
| `approvals.rs:973-974` | `public_hex` deriva la clave pública con `SigningKey::from_bytes` | acoplado |
| `approvals.rs:26-27` | dominios `PRAETORE_MCP_LOCAL_APPROVAL_V1` y `..._EXEC_V1` | formato |
| `crates/praetore-gateway-service/src/main.rs:1` | `use ed25519_dalek::{Signer, SigningKey}` | acoplado |
| `main.rs:75-94` | secretos de atestador: 64 hex en minúsculas, `[u8; 32]` | acoplado |
| `main.rs:146-196` | `LocalExecutionSigner` guarda `SigningKey` y firma el mensaje que le pasan | acoplado |
| `crates/praetore-cli/src/main.rs:1` | `use ed25519_dalek::{Signer, SigningKey}` | acoplado |
| `main.rs:142-178` | `LocalExecutionSigner` de la demo, `from_bytes` y `sign` | acoplado |
| `main.rs:511-513` | `init` publica el pin del approver desde `SigningKey::from_bytes` | acoplado |
| `main.rs:782-783` | `doctor` compara el pin con `from_bytes` | acoplado |
| `main.rs:1755-1757` | `approve` carga `approver.key` con `from_bytes` | acoplado |
| `main.rs:2143`, `main.rs:2262` | derivan la clave pública con `from_bytes` para el pin | acoplado |
| `crates/praetore-console/src/aprobador.rs:15` | `use ed25519_dalek::{Signer, SigningKey}` | acoplado |
| `aprobador.rs:77-98` | `ApproverSigner` guarda `SigningKey`, secreto `[u8; 32]` | acoplado |
| `aprobador.rs:140-154` | `sign` hace `self.key.sign(&message).to_bytes()` y lo guarda en hex | acoplado |

`ExecutionAttestationSigner` (`crates/praetore-receipt/src/lib.rs:356`) no
nombra un algoritmo. `ExecutionAttestation::create` vuelve a fijar Ed25519
en `lib.rs:498`: rechaza una firma cuyo `len()` no es 64. La consola, el
CLI y `praetore-gateway-service` implementan el trait con `SigningKey`.

Dependencia directa de producción sobre `ed25519-dalek` 2:

| Manifiesto | Línea |
|---|---|
| `crates/praetore-core/Cargo.toml` | 17, features `rand_core` y `zeroize`. `rand_core` 0.6 en la línea 19 |
| `crates/praetore-mcp/Cargo.toml` | 22, `= "2.2.0"` (el resto del workspace pide `"2"`) |
| `crates/praetore-gateway-service/Cargo.toml` | 27 |
| `crates/praetore-cli/Cargo.toml` | 23 |
| `crates/praetore-console/Cargo.toml` | 14 |

`Cargo.lock` raíz resuelve `ed25519-dalek` 2.2.0 con `rand_core` 0.6.4
(`Cargo.lock:406-413`). El mismo lock también trae `rand_core` 0.10.1
(`Cargo.lock:1610`), por otras crates. `OsRng` importado como `rand_core::OsRng`
en el núcleo es el de 0.6.

## Tamaños y formato serializado

Igualdad de 64 bytes de firma, o 128 hex en minúsculas:

| Sitio | Comprobación |
|---|---|
| `crates/praetore-core/src/canonical.rs:213-222` | `is_canonical_signature_hex`: longitud 128, solo `0-9a-f` |
| `evidence.rs:445` | el recibo usa esa función antes de `Signature::from_slice` |
| `storage_record.rs:214` | el registro de almacenamiento también |
| `approvals.rs:958` | la aprobación MCP también |
| `key_rotation.rs:82-85` | `is_lower_hex` de la firma a 128, y de la clave pública nueva a 64 hex |
| `receipt/src/lib.rs:498` | `signature.len() != 64` sobre los bytes que devolvió el signer |
| `receipt/src/approval.rs:361` | igual, en el cierre de aprobación vencida |
| `identity.rs:218` | `Signature::from_slice` rechaza una longitud distinta de 64. `HumanApprovalDecision::verify_signature` (`approval.rs:146-152`) no mira la longitud: `is_lower_hex` (`approval.rs:392`) solo mira el alfabeto. La longitud la pone dalek |

Clave pública o secreta de 32 bytes:

| Sitio | Comprobación |
|---|---|
| `identity.rs:192` | único filtro de clave pública del núcleo: exactamente 32 bytes, luego `VerifyingKey::from_bytes` y `is_weak` |
| `gateway-service/src/main.rs:83-94` | archivo de secreto: 64 hex, `[u8; 32]` |
| `praetore-mcp/src/store.rs:303-305` | `random_secret` llena `[u8; 32]` |
| `store.rs:395-417` | el archivo de clave exige `algorithm == "ed25519"` y 32 bytes |
| `store.rs:309-314` | el archivo escribe `algorithm: "ed25519"` |
| `praetore-cli/src/main.rs:610-614` | `random_secret` llena `[u8; 32]` con `OsRng.try_fill_bytes` |
| `receipt/src/outcomes.rs:165` | pin hex de 64 caracteres, luego `VerifiedPublicKey::from_bytes` |
| `engine.rs:183-203` | el pin de emisor serializa `algorithm: "ed25519"` y lo exige al leer |

El key id no es la clave. Es `hex(SHA-256(dominio || clave pública))`, 64
hex. Estos dominios llevan el algoritmo dentro del texto firmado de forma
indirecta (entra en el id, y el id entra en el payload):

| Constante | Línea |
|---|---|
| `PRAETORE_AGENT_KEY_V1\0ed25519\0` | `identity.rs:12` |
| `PRAETORE_ATTESTER_KEY_V1\0ed25519\0` | `evidence.rs:27` |
| `PRAETORE_ISSUER_KEY_V1\0ed25519\0` | `engine.rs:124` y `authority.rs:14` (el mismo literal, dos sitios) |
| `PRAETORE_SAFETY_SOURCE_KEY_V1\0ed25519\0` | `safety_ingest.rs:60` |
| `PRAETORE_SAFETY_INGEST_KEY_V1\0ed25519\0` | `safety_ingest.rs:63` |
| `PRAETORE_SAFETY_NAMESPACE_KEY_V1\0ed25519\0` | `safety_namespace.rs:71` |

Dominios de firma (no llevan el nombre del algoritmo, sí separan el rol):

| Dominio | Línea |
|---|---|
| `PRAETORE_EVIDENCE_V1\0`, `PRAETORE_EVIDENCE_V2\0` | `evidence.rs:25-26` |
| `PRAETORE_INTENT_V1\0` | `identity.rs:14` |
| `PRAETORE_INTENT_V2\0` | `authorization.rs:18` |
| `PRAETORE_AUTHORITY_V1\0` | `authority.rs:13` |
| `PRAETORE_KEY_ROTATION_V1\0` | `key_rotation.rs:14` |
| `PRAETORE_STORAGE_RECORD_V1\0` | `storage_record.rs:13` |
| `PRAETORE_SAFETY_EVENT_V1\0` | `safety_ingest.rs:55` |
| `PRAETORE_SAFETY_RECORD_V1\0` | `safety_ingest.rs:57` |
| `PRAETORE_SAFETY_NAMESPACE_V1\0` | `safety_namespace.rs:65` |
| `PRAETORE_HUMAN_APPROVAL_V1\0` | `receipt/src/approval.rs:15` |
| `PRAETORE_APPROVAL_EXPIRED_V1\0` | `approval.rs:16` |
| `PRAETORE_EXECUTION_ATTESTATION_V1\0` | `receipt/src/lib.rs:28` |
| `PRAETORE_MCP_LOCAL_APPROVAL_V1\0` | `approvals.rs:26` |
| `PRAETORE_MCP_LOCAL_APPROVAL_EXEC_V1\0` | `approvals.rs:27` |

`safety_namespace.rs:61-64` documenta un test que recorre los literales de
dominio del repositorio y rechaza que uno sea prefijo de otro. Ese test no
ve el literal `"ed25519"` de los key id.

## Generación de claves y RNG

`SigningKey::generate(&mut OsRng)` con `use rand_core::OsRng` (crate 0.6):

| Sitio | Tipo que construye |
|---|---|
| `evidence.rs:91` | `EvidenceAttesterKey::generate` |
| `identity.rs:157` | `AgentKeyPair::generate` |
| `safety_ingest.rs:214-216` | macro `signing_role!`, expandida dos veces |
| `safety_ingest.rs:238-245` | expansión `SafetySourceKey` |
| `safety_ingest.rs:247-254` | expansión `SafetyIngestKey` |
| `safety_namespace.rs:252` | `SafetyNamespaceKey::generate` |

La macro explica el "safety_ingest.rs x2" del hallazgo previo: una línea
fuente, dos tipos.

Otra generación, que no llama a `SigningKey::generate`. Llena 32 bytes con
`OsRng` de `rand_core` 0.6 y luego `from_bytes` o `from_secret_bytes`:

| Sitio | Llamada |
|---|---|
| `praetore-mcp/src/store.rs:8`, `store.rs:305` | `OsRng.fill_bytes` |
| `praetore-mcp/src/approvals.rs:15`, `approvals.rs:1192` | `OsRng.fill_bytes` |
| `praetore-mcp/src/cli.rs:10`, `cli.rs:1000` | `OsRng.fill_bytes` |
| `praetore-cli/src/main.rs:16`, `main.rs:612` | `OsRng.try_fill_bytes` |
| `examples/claude-code-hook/src/main.rs:47`, `main.rs:2161` | `OsRng.try_fill_bytes`. El ejemplo no depende de dalek. Construye `AgentKeyPair::from_secret_bytes` (`main.rs:367`) y `EvidenceAttesterKey::from_secret_bytes` (`main.rs:382`) |

El hook fija `rand_core` 0.6 en `examples/claude-code-hook/Cargo.toml:24`.

## Tests y ejemplos que nombran dalek

No son producción. Rompen el mismo acoplamiento si el tipo cambia. Líneas
con `SigningKey`, `VerifyingKey` o `Signature` de dalek:

| Archivo | Líneas |
|---|---|
| `crates/praetore-gateway/tests/enforcement.rs` | 5, 74, 82, 1062, 1085, 1097, 1109, 1122, 1136, 1157, 1162, 1171, 1234, 2964, 3228, 3245, 4050, 4087, 4131, 4353, 4734, 6346, 6605, 6695 |
| `crates/praetore-core/tests/safety_namespace.rs` | 10, 914 |
| `crates/praetore-gateway-service/src/approver_bindings.rs` | 133, 137, dentro de `#[cfg(test)]` |
| `crates/praetore-gateway-service/src/main.rs` | 758, test `execution_signer_produces_ed25519_signatures_with_a_neutral_key_id` bajo `#[cfg(test)]` en 752 |
| `crates/praetore-console/src/tests_bandeja.rs` | 11, 195 (`ed25519_dalek::VerifyingKey`), 220, 270 (`Signature::from_bytes`), 1143 |
| `crates/praetore-console/src/tests_paquete.rs` | 7, 439, 467, 490, 601, 808, 890, 933, 1059, 1067, 1076, 1150, 1163, 1178, 1656 |
| `crates/praetore-replay-postgres/tests/postgres.rs` | 1, 70, 74, 729, 892 |
| `crates/praetore-cli/src/main.rs` | `mod tests` en 1900. `from_bytes`: 2445, 2531, 2589, 3137, 3514, 3811, 4498, 4585, 4674, 5217, 5319, 5445 |
| `crates/praetore-receipt/tests/verify.rs` | 259, 268 |
| `crates/praetore-receipt/examples/demo_receipt_verify.rs` | 18, 47, 171. Semilla `[u8; 32]` en 36-39 |

El literal `"ed25519"` en tests, además de los de producción: `engine.rs:1790`,
`engine.rs:4032`, `evidence.rs:806`, `identity.rs:271`, `identity.rs:292`,
`identity.rs:302`, `identity.rs:309`, `identity.rs:323`, `policy.rs:1835`,
`authorization.rs:485`, `crates/praetore-core/tests/canopy_port.rs:324`,
`crates/praetore-core/tests/safety_namespace.rs:853-855`,
`fuzz/fuzz_targets/engine_evaluate_dev.rs:22`.

## Clippy

El único `clippy.toml` del repositorio es `crates/praetore-mcp/clippy.toml`.
Niega `Expiry::at`. No hay `disallowed-types` para `ed25519_dalek`. No hay
`clippy.toml` en la raíz. `assurance.yml:121` corre
`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
y no añade esa negación.

## ed25519-dalek 3.0, PRs #101 y #103

Ramas no modificadas. Lectura con `gh pr view`, `gh pr checks`, `git show`
de los archivos del PR y el log del job que falla. Commit de base de ambos
PRs: anteriores a `27ceddbb`. El código que el compilador señala
(`SigningKey::generate(&mut OsRng)` en esas cuatro líneas) es el mismo en
`27ceddbb`.

Los dos PRs hacen la misma operación sobre archivos distintos.

| | #101 | #103 |
|---|---|---|
| URL | https://github.com/Mavericksantander/praetore/pull/101 | https://github.com/Mavericksantander/praetore/pull/103 |
| Rama | `dependabot/cargo/fuzz/ed25519-dalek-3.0.0` | `dependabot/cargo/examples/claude-code-hook/ed25519-dalek-3.0.0` |
| Head | `cacb70d68d95540df088941a1445b8ecb911cb0a` | `e760638529930a1eb81e2b0213f0c648ab70162a` |
| Estado | OPEN, no draft, MERGEABLE | OPEN, no draft, MERGEABLE |
| Archivos (`gh pr view --json files`) | `crates/praetore-core/Cargo.toml`, `fuzz/Cargo.lock` | `crates/praetore-core/Cargo.toml`, `examples/claude-code-hook/Cargo.lock` |
| `Cargo.lock` raíz en la rama (`git show`) | `ed25519-dalek` 2.2.0, línea 406 | igual, 2.2.0, línea 406 |
| Lock que sí sube | `fuzz/Cargo.lock`: dalek 3.0.0, depende de `rand_core` 0.10.1 | `examples/claude-code-hook/Cargo.lock`: dalek 3.0.0, `rand_core` 0.10.1, checksum `6ebaa1a2bf1290ab3bfe5a7b771d050ebffab2711c19a81691c683a5144a25de` |
| Manifiesto de core en la rama | `ed25519-dalek` version `"3"`, features `rand_core` y `zeroize`. `rand_core` sigue en `"0.6"` | igual |

`gh pr checks` salió con código 1 en los dos. Conteos leídos de esa salida,
run `43958332336` para #101 y `43958343888` para #103: 15 fail, 5 pass,
4 skip. Los pass son Actions pinned, Console page, Dependency advisory
audit, Release signature, CycloneDX SBOM. Los skip son GitHub Release,
Release checksums, Sign release checksums y el smoke de `praetore-mcp`.
No se leyó el log de los 15. Los que sí se leyeron:

1. Workspace, los dos PRs. Job `Rust tests, lint, and format`
   (#101 `133618716927`, #103 `133618754865`). Paso
   `cargo test --workspace --locked`. Texto:

   `error: cannot update the lock file /home/runner/work/praetore/praetore/Cargo.lock because --locked was passed to prevent this`

   El job termina ahí. No hay `E0277` en ese log. El manifiesto pide dalek 3
   y el lock raíz sigue en 2.2.0.

2. #101, job `Fuzz smoke` `133618717047`. `fuzz/Cargo.lock` sí está en 3.0.0,
   así que compila. Cinco `error[E0277]`, y después
   `error: could not compile praetore-core (lib) due to 5 previous errors`.
   Rutas del log:

   - `crates/praetore-core/src/evidence.rs:91:47`
   - `crates/praetore-core/src/identity.rs:157:47`
   - `crates/praetore-core/src/safety_ingest.rs:216:55` (dos veces)
   - `crates/praetore-core/src/safety_namespace.rs:252:47`

   Mensaje: `the trait bound OsRng: ed25519_dalek::rand_core::CryptoRng is not satisfied`.
   Nota de ese job: `the trait TryRng is not implemented for OsRng`, requerida
   para `CryptoRng`. La firma que cita el compilador, en
   `ed25519-dalek-3.0.0/src/signing.rs:213`:

   `pub fn generate<R: CryptoRng + ?Sized>(csprng: &mut R) -> SigningKey`

   Cargo llegó a `Checking ed25519-dalek v3.0.0` antes de esos errores. En
   este job no apareció otro `error[E`. El typecheck se detiene en
   `praetore-core`. No hay evidencia, en estos logs, de un fallo distinto en
   cli, consola, mcp o gateway-service: esos crates no se compilaron aquí.

3. #103, job `Claude Code hook example (standalone)` `133618755012`. Paso
   `cargo clippy --manifest-path examples/claude-code-hook/Cargo.toml --all-targets --locked`.
   El lock del ejemplo está en dalek 3.0.0 y el ejemplo compila `praetore-core`.
   Los mismos cinco `E0277` en las mismas cuatro líneas, y
   `could not compile praetore-core (lib) due to 5 previous errors`.
   La nota secundaria de este job dice `the trait DerefMut is not implemented for OsRng`,
   no `TryRng`. El bound que falla es el mismo: `ed25519_dalek::rand_core::CryptoRng`.

4. #103, job `Fuzz smoke` `133618754645`. Este PR no toca `fuzz/Cargo.lock`.
   Paso `cargo +nightly check --manifest-path fuzz/Cargo.toml --locked`:

   `error: cannot update the lock file /home/runner/work/praetore/praetore/fuzz/Cargo.lock because --locked was passed to prevent this`

`OsRng.fill_bytes` y `try_fill_bytes` no salen en esos errores. El fallo
observado es solo `SigningKey::generate`.

## Hallazgos repetidos

Misma causa en más de un sitio. El chequeo propuesto es determinista: falla
el build si el patrón vuelve, sin revisar prosa.

| Id | Repetición | Dónde | Chequeo |
|---|---|---|---|
| R1 | `SigningKey::generate(&mut OsRng)` | 4 líneas fuente, 5 expansiones. Es el `E0277` de dalek 3 | `rg` de `SigningKey::generate` con un solo permitido, el módulo de firma |
| R2 | `Signature::from_slice` más `verify_strict` | `identity.rs:218`, `evidence.rs:450`, `key_rotation.rs:112` | el mismo `rg` sobre `verify_strict` fuera de ese módulo |
| R3 | literal `"ed25519"` y el algoritmo dentro del key id | 6 dominios de key id, pins, archivos de clave, `evidence.rs:602` | el literal `ed25519` en `*.rs` solo en el módulo y en los golden ya versionados |
| R4 | tres `Cargo.lock` (raíz, `fuzz/`, `examples/claude-code-hook/`) | #101 y #103: suben un lock anidado a 3.0.0, dejan la raíz en 2.2.0, y cambian el manifiesto de core a `"3"` | script que lee la versión de `ed25519-dalek` en los tres locks y falla si difieren. `--locked` ya cubre manifiesto contra su lock, y es lo que falló en CI. No cubre, por sí solo, que los tres locks avancen juntos cuando un PR solo toca uno |
| R5 | `SigningKey` en el binario | mcp, gateway-service, cli, consola, además del núcleo | `disallowed-types` (abajo) |
| R6 | tres maneras de pedir 64 bytes | 128 hex (`canonical.rs:217`), `len() != 64` (`receipt` `lib.rs:498`, `approval.rs:361`), `Signature::from_slice` (`identity.rs:218`). La aprobación humana no comprueba la longitud ella misma | una función del módulo, un test de longitud 31, 32, 33, 63, 64, 65 |

## Eliminación estructural

Un módulo, por ejemplo `praetore_core::signature`, dueño de `ed25519_dalek`.
Tipos opacos `Signer`, `PublicKey`, `Signature`. Fuera de ese archivo no hay
`SigningKey`, `VerifyingKey` ni `Signature` de dalek.

- `Signer::generate` es el único `SigningKey::generate`. El `OsRng` que
  reciba es el `CryptoRng` de la versión de `rand_core` que dalek declara
  (en 3.0.0, 0.10.1, según el lock del PR). Quien hoy llama
  `OsRng.fill_bytes` sobre `[u8; 32]` llama `Signer::generate` o
  `Signer::from_secret_bytes`.
- `PublicKey::from_bytes` conserva el rechazo de longitud y de clave débil
  que hoy está en `identity.rs:191-201`.
- `Signature::from_canonical_hex` es la única puerta de 128 hex y 64 bytes.
  `verify_attester_signature` y `verify_new_key_possession` pasan a
  `PublicKey::verify(domain, payload, signature)`.
- El algoritmo deja de ser `String` libre. Un enum de un solo caso, serializado
  como `"ed25519"`. Los seis dominios de key id se construyen en el módulo
  a partir de ese caso, para que un segundo algoritmo no se añada pegando
  otro literal.
- Clippy `disallowed-types` para `ed25519_dalek::SigningKey`,
  `ed25519_dalek::VerifyingKey` y `ed25519_dalek::Signature`, en un
  `clippy.toml` de la raíz y también en `crates/praetore-mcp/clippy.toml`,
  porque ese crate ya tiene el suyo y es el único. Además, un paso de CI con
  `rg` que falle si `ed25519_dalek::` aparece fuera del módulo. El `rg` no
  depende de cuál `clippy.toml` gana cuando hay uno anidado.
- Test del módulo, en el mismo crate: longitudes malas, clave débil de ceros
  (hoy `identity.rs`, test `rejects_weak_ed25519_public_keys_before_they_are_fingerprinted`),
  y un vector golden de firma que ya viva en `docs/golden/`.
- El script de los tres locks, en el job que ya corre `--locked`.

Eso quita R1 a R6 por tipos, API, clippy y CI. Un comentario de revisión no
los quita.

## Invariante de firma, propuesta

No hay modelo TLA+ que citar. Propuesta, no es un artefacto del repositorio:

`SigVerify`. Para un dominio `d`, un payload `p` y una clave `sk` con
pública `pk`:

- `verify(d, p, sign(sk, d, p), pk)` acepta.
- `verify` rechaza si cambia `d`, o `p`, o `pk`.
- Dos dominios distintos no verifican la firma del otro.

El código que tendría que ser esa operación es uno solo:
`VerifiedPublicKey::verify_domain_message` (`identity.rs:212`). Hoy
`evidence.rs:450` y `key_rotation.rs:112` son otras dos. Hasta que no sean
la misma función, el invariante no tiene un solo sitio que modelar.

## Qué no dice este informe

- No dice que dalek 3 rompa `from_bytes`, `Signer::sign` o `fill_bytes`.
  Esos sitios no aparecen en los logs leídos.
- No dice que los 15 checks rojos de #101 y #103 sean 15 fallos distintos.
  Solo están leídos el job de `cargo test --workspace --locked`, el fuzz de
  cada PR y el clippy del hook en #103.
- No asigna un nivel de madurez.
