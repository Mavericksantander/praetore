# SAF-11 · Custodia de llaves y log de transparencia de recibos (propuesta)

Estado: **propuesta, solo documento.** No contiene código de producción.
Ninguna decisión está tomada: todas esperan al CTO.
Base: `origin/main` en `97fa755`.
Nombre: sigue la convención `SAF-NN`. El número es provisional.
Relación: el PR #18 (cadena del journal en `praetore-verify`) cubre una parte
de §5. Esta propuesta se ajusta a lo que ese PR termine garantizando.

## 1. Problema

El argumento central de PRÆTORE es que un tercero puede verificar los recibos
sin confiar en el operador. Hoy eso vale para la **autenticidad** de un recibo
aislado, pero no para estas dos cosas:

1. **Custodia:** la llave que firma los recibos vive en memoria del proceso y
   entra por una variable de entorno. Quien la obtiene puede fabricar recibos
   válidos, incluidos recibos con fechas pasadas.
2. **Completitud:** un recibo firmado no prueba que no existan otros.
   Un operador puede borrar el recibo de una acción incómoda, o reemplazar el
   journal entero, y nada lo delata.

Un auditor necesita que ambas se cumplan. Una llave en HSM sin log permite
ocultar recibos. Un log sin custodia permite que quien tenga la llave lo
regenere completo de forma coherente.

## 2. Estado actual verificado (solo lectura)

- **Llaves de servicio en variables de entorno, como hex:**
  - `crates/praetore-gateway-service/src/main.rs:228` y `:358`:
    `PRAETORE_GATEWAY_EVIDENCE_ATTESTER_KEY_HEX`.
  - `:262` y `:359`: `PRAETORE_GATEWAY_EXECUTION_ATTESTER_KEY_HEX`.
- **Firma en proceso:** `crates/praetore-core/src/evidence.rs:67-105`.
  `EvidenceAttesterKey` contiene un `ed25519_dalek::SigningKey`
  (`from_secret_bytes`, `generate`). `Evidence::sign` (`:320`) firma
  localmente. `identity.rs:145` hace lo mismo con la llave del agente.
- **Identificación de la llave:** cada recibo lleva `attester_key_id` y
  `attester_algorithm` (`evidence.rs:49-50`). El `key_id` se deriva de la
  llave pública (`:104-110`).
- **Verificación con un solo pin y sin vigencia:**
  - `praetore-verify evidence --attester-pin HEX_FILE` recibe **una** llave
    pública y no admite ventana de validez.
  - Los pines de issuer, en cambio, sí la tienen (`issuer-pins.jsonl`,
    `"validity":{"not_before","not_after"}`; `engine.rs:131-136`).
- **Fecha de decisión:** existe `decided_at` (`evidence.rs`), pero la pone
  el mismo proceso que firma, así que no prueba nada frente a quien tiene la
  llave.
- **Journal:**
  - Las filas en PostgreSQL son append-only por triggers, con RLS
    (migraciones 0001–0012).
  - Ningún recibo referencia al anterior, no hay raíz agregada y nada se
    publica fuera del operador.
  - El dueño de la base de datos sigue pudiendo borrar filas: #41 lo impide
    para el rol de runtime, no para el rol que es dueño de las tablas.
- **Rotación:** `key_rotation.rs` cubre la rotación de la llave del
  **agente** (prueba de posesión). No hay rotación para el attester ni para
  la llave de ejecución.

## 3. Decisiones propuestas

| # | Decisión | Estado |
|---|---|---|
| 1 | La firma pasa por un trait `Signer` (llave pública, `key_id`, `sign(dominio, mensaje)`). `EvidenceAttesterKey` y la llave de ejecución pasan a ser una implementación más (`LocalSigner`). Los formatos de recibo no cambian: solo cambia quién firma. | PROPUESTA |
| 2 | Implementaciones: AWS KMS y GCP KMS (Ed25519 o, si el KMS no lo ofrece, ECDSA P-256 con su propio `attester_algorithm`), y PKCS#11 para HSM. Cada una va en un crate opcional; `praetore-core` no depende de ningún SDK de nube. | PROPUESTA |
| 3 | En los modos `http`/`sandbox`, el servicio **no arranca** con una llave de firma entregada como variable de entorno, salvo con un opt-in explícito y con nombre alarmante. El demo local sigue igual. | PROPUESTA |
| 4 | **Pines con vigencia para attester y ejecución:** archivo `attester-pins.jsonl` con el mismo formato que los pines de issuer (`key_id`, `public_key`, `validity`). Un recibo verifica solo si `decided_at` cae dentro de la vigencia de la llave que lo firmó. `--attester-pin HEX_FILE` se mantiene como caso de un solo pin sin vigencia. | PROPUESTA |
| 5 | **Revocación con fecha de corte:** una llave comprometida se marca `revoked_at`. Desde ese momento no se cree nada que haya firmado. Lo anterior sigue valiendo **solo** si un checkpoint anclado (decisión 8) lo cubre, porque `decided_at` por sí solo lo controla quien tiene la llave. | PROPUESTA |
| 6 | **Log de transparencia:** cada recibo cerrado (evidencia más attestation de ejecución) se agrega como hoja de un árbol de Merkle append-only por tenant, con el esquema de hashes de RFC 6962/9162 y prefijos de dominio propios. | PROPUESTA |
| 7 | **Checkpoints firmados** periódicos (cada N recibos o cada T segundos, lo que ocurra primero): `{log_id, tenant, tree_size, root_hash, timestamp}`, firmados por una llave de log **distinta** de la del attester. Formato compatible con *signed note* / *checkpoint* de transparency-dev, para poder reutilizar witnesses existentes. | PROPUESTA |
| 8 | **Anclaje externo** de cada checkpoint en algo que el operador no controla. Configurable: sello de tiempo RFC 3161 de una TSA, y/o witnesses de terceros que cosignan checkpoints, y/o entrega directa al auditor. Sin anclaje, el log solo detecta borrados hechos por alguien **sin** la llave del log; esto se documenta así. | PROPUESTA |
| 9 | **Pruebas para terceros:** `praetore-verify` agrega `inclusion` (este recibo está en el checkpoint C), `consistency` (el checkpoint C2 extiende C1 sin reescribirlo) y `audit` (con un export del journal y los checkpoints anclados: no hay huecos, ni duplicados, ni hojas que no correspondan a recibos válidos). Ninguna requiere red ni confiar en el operador. | PROPUESTA |
| 10 | La cadena de #18 (si se mergea) se mantiene como verificación local barata, pero la garantía para terceros es la del árbol más el anclaje. Se documenta qué detecta cada una. | PROPUESTA |

## 4. Custodia: detalle (decisiones 1–5)

```text
trait Signer: Send + Sync {
    fn algorithm(&self) -> &'static str;      // "ed25519" | "ecdsa-p256-sha256"
    fn public_key(&self) -> &[u8];
    fn key_id(&self) -> String;                // derivado de la llave pública, igual que hoy
    fn sign(&self, domain: &[u8], message: &[u8]) -> Result<Vec<u8>, SignerError>;
}
```

- **Errores:** `SignerError::Unavailable` (KMS o HSM caído) se trata como
  error transitorio, igual que `TrustedClockUnavailable` en #42. El gateway
  no despacha y la ejecución aprobada queda reintentable. Nunca se cae a una
  llave local.
- **Latencia:** una firma por KMS cuesta entre 10 y 50 ms. Se firma una vez
  por decisión y otra por cierre de ejecución, y nunca se agrupan firmas de
  decisiones distintas.
- **Algoritmo:** si el KMS no ofrece Ed25519, aparece un nuevo
  `attester_algorithm` y la versión de esquema de evidencia sube. Los
  verificadores existentes rechazan ese algoritmo hasta soportarlo, que es
  lo esperado.
- **Rotación:** se agrega un pin nuevo con `not_before = T`, se cambia el
  `Signer` y se cierra la vigencia del pin anterior con `not_after = T + margen`.
  Los recibos antiguos siguen verificando con su propio pin.

## 5. Completitud: detalle (decisiones 6–10)

**Hojas.** `leaf = H(0x00 ‖ "PRAETORE_LOG_LEAF_V1\0" ‖ canonical(receipt))`.
Se agregan en el mismo orden en que se cierran los recibos en el journal.
El índice de la hoja se guarda junto al recibo.

**Qué detecta cada mecanismo:**

| Ataque | Cadena local (#18) | Árbol + checkpoint firmado | + anclaje externo |
|---|---|---|---|
| Borrar un recibo del medio | sí | sí | sí |
| Truncar el final | no (salvo que el auditor conozca la cola) | sí, respecto al último checkpoint visto | sí |
| Reordenar | sí | sí | sí |
| Mostrar logs distintos a auditores distintos (fork o equivocation) | no | no | sí, si los witnesses comparan |
| Regenerar todo con la llave del log | no | no | sí, contra los checkpoints anclados previos |
| Recibo omitido antes de entrar al log (nunca se agregó) | no | no | no: ver §6 |

**Almacenamiento:**
- Tabla `praetore.transparency_log` (hojas e índices) y
  `praetore.log_checkpoints`, ambas append-only con el mismo patrón de
  triggers y RLS.
- La raíz se calcula en el gateway y la base solo la persiste.
- Migración nueva; ninguna migración existente cambia.

**El modo local (`praetore-mcp`)** usa el mismo árbol sobre su journal JSONL,
con checkpoints locales. El anclaje queda opcional: sin él, la garantía local
se documenta tal cual es.

## 6. Límites honestos

- **Un recibo que nunca se emitió no se detecta.** Si el gateway ejecuta una
  acción sin generar recibo, ni el árbol ni el anclaje lo notan. Esto se
  mitiga con la mediación obligatoria (herramientas que solo aceptan llamadas
  del gateway, como en `deploy/kubernetes`), no con criptografía.
- **Los timestamps del gateway no son confiables frente a quien tiene la
  llave.** Solo el anclaje (TSA o witness) da una cota temporal externa.
- **El KMS acota el daño, pero no evita que un gateway comprometido pida
  firmas** mientras esté comprometido. La revocación con fecha de corte
  (decisión 5), junto con checkpoints anclados, limita la ventana.

## 7. Orden de implementación sugerido

1. Trait `Signer` + `LocalSigner` (sin cambio de comportamiento), y pines con
   vigencia para attester y ejecución en `praetore-verify` y en
   `praetore-receipt`.
2. Implementación de KMS (empezando por uno, según el cliente piloto) y la
   decisión 3 para los modos de producción.
3. Árbol de Merkle, checkpoints firmados, migración y `praetore-verify
   inclusion|consistency`.
4. Anclaje (RFC 3161 primero, porque no depende de terceros dispuestos a
   operar witnesses) y `praetore-verify audit`.
5. Revocación con fecha de corte.

Cada paso, como en SAF-10: primero los tests de propiedad.

## 8. Pendientes para el CTO

- Aprobar o ajustar las decisiones 1–10.
- Qué KMS va primero (depende del piloto).
- Granularidad del log: ¿uno por tenant (aislamiento y exportación por
  cliente) o uno global con hojas etiquetadas por tenant (más fácil de
  anclar)? Se propone uno por tenant.
- Frecuencia de checkpoints por defecto (se propone cada 60 s o cada 1000
  recibos).
- Si los checkpoints se publican en un lugar público o solo se entregan al
  auditor de cada tenant.
