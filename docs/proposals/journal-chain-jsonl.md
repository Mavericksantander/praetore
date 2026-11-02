# Propuesta: export encadenado del journal (JSONL)

**Estado: implementado** (rama `feat/journal-chain`, 31-oct-2026), con los
límites de "Qué NO prueba", que siguen vigentes.

- Formato y link: `praetore_core::journal_chain`. Productor y verificador
  usan la misma función de link.
- Productor: `praetore journal-export (--receipts-dir DIR | --tenant UUID)
  --attester-pin HEX_FILE --output NUEVO`. Desde un directorio encadena los
  `*.json` en orden de nombre; desde el journal lee las filas del tenant en
  `praetore.execution_journal` ordenadas por `(created_at, request_id,
  agent_id)` (`agent_id` desempata dos agentes que reusan un `request_id`;
  los UUID se comparan byte a byte, igual que su texto hex en minúsculas).
  Verifica cada recibo contra la clave fijada antes de encadenarlo y nunca
  sobrescribe el archivo de salida.
- Verificador: `praetore-verify journal --journal JSONL --attester-pin
  HEX_FILE [--expected-head HEX] [--policy PATH]`. Viene de la rama
  `feat/journal-chain-verifier` (commit `bfeade5`), integrado por
  cherry-pick y alineado con `main`.
- Evidencia: `examples/claude-code-hook/evidence/0{3,4,5}-*/journal-chain.jsonl`,
  heads en `examples/claude-code-hook/evidence/VERIFY.md`, job de CI
  `journal-chain`.

## Formato

- Archivo UTF-8, una entrada por línea; cada línea, incluida la última,
  termina en `\n`. Sin líneas vacías ni `\r`. Un archivo vacío es inválido.
- Cada línea es un objeto JSON con exactamente estos campos (cualquier otro
  campo se rechaza):
  - `seq`: entero sin signo. Es 0 en la primera línea y aumenta de 1 en 1.
  - `prev`: 64 caracteres hex en minúsculas. En la primera línea son 64
    ceros. En las siguientes es el `link` de la entrada anterior.
  - `evidence`: un recibo `Evidence` completo, tal como lo emite
    `Evidence::to_json`. Se valida con `Evidence::from_json`, que rechaza
    claves duplicadas y campos desconocidos.
- Cada `evidence_id` aparece una sola vez en el archivo.

## Storage records and the database chain (format v1, extension)

Facts about the journal database itself, today only the adoption of a legacy
0001-0009 schema (`kind: "legacy_baseline_adopted"`), are signed **storage
records**. The migration runner writes one in the same transaction as the
adoption, into `praetore.storage_records` (migration 0015, append-only by
trigger), signed with the evidence attester key that the binary passes in
(`MigrationOptions::record_signer`). Without a signer, adoption is refused.

- A `StorageRecord` v1 is a JSON object with exactly `schema_version` (1),
  `kind`, `record_id`, `recorded_at` (RFC 3339), `database`,
  `database_oid`, `recorded_by`, `migrations` (`[{version, checksum}]`),
  `structure_sha256`, `key_id` (the attester key id), `record_hash` and
  `signature`. The payload is every field but the last two, as compact JSON
  in that order; `record_hash = hex(SHA-256("PRAETORE_STORAGE_RECORD_V1\0" ||
  payload))` and `signature = hex(Ed25519("PRAETORE_STORAGE_RECORD_V1\0" ||
  payload))`.
- **Database chain** (`praetore journal-export --database --attester-pin
  HEX_FILE --output NEW`): the storage records in `(created_at, record_id)`
  order. Each line is `{"seq","prev","record"}`, with the record link
  `SHA-256("PRAETORE_JOURNAL_RECORD_V1\0" || u64_be(seq) || ascii(prev) ||
  ascii(record_hash) || ascii(signature))`.
- **Tenant chain** (`--tenant UUID`): when the database has storage records,
  its first line is a reference to the database chain read in the same
  snapshot: `{"seq":0,"prev":"<64 zeros>","database_head":{"schema_version":1,
  "entries":N,"head":"<64 hex>"}}`, with link
  `SHA-256("PRAETORE_JOURNAL_DATABASE_HEAD_V1\0" || u64_be(seq) ||
  ascii(prev) || ascii(head) || u64_be(entries))`. The receipts follow, as
  before. Without storage records the tenant chain is exactly the v1 format.
- Every line has exactly one of `evidence`, `record` or `database_head`. A
  chain holds either records only (database chain) or receipts with an
  optional first-line reference (tenant chain); anything else is refused
  (`JOURNAL_CHAIN_FAIL`). Each kind has its own link domain, so a record
  line cannot stand in for a receipt line.
- `praetore-verify journal` verifies both kinds (record hash and signature
  against the attester pin, `record_id` unique). With `--database-journal
  JSONL` (verified too) or `--expected-database-head HEX`, a tenant chain
  must carry a matching reference (`JOURNAL_HEAD_MISMATCH` otherwise).
- **Attester key rotation.** Records and receipts keep the signature of the
  key that was current when they were written; nothing is re-signed (the
  table is append-only). `praetore journal-export` and `praetore-verify
  journal` accept `--attester-pin` more than once (up to 16 keys). Each
  line is checked against the pinned key whose key id it names (`key_id` of
  a record, `attester_key_id` of a receipt); a line signed by a key outside
  the set fails, naming that key (`AUTH_FAIL` for a receipt,
  `EVIDENCE_FAIL` for a record). `praetore-verify journal` reports, in
  `attester_key_ids`, how many entries of `--journal` each key id signed,
  so that entries signed by a retired key after the rotation are visible;
  with `--database-journal`, `database_attester_key_ids` does the same for
  that file (`null` without it). After a rotation, pass the retired key's
  pin together with the current one: with only the current pin, every
  export of a database adopted before the rotation fails
  (`journal-export --tenant` reads the database chain to reference its
  head), and so does `praetore-verify` on the database chain or with
  `--database-journal`. A tenant chain file checked alone needs only the
  keys that signed its receipts: its reference line is not signed and
  proves nothing without the database chain. The head of a chain does not
  depend on which pins were given. Pinning a retired key keeps accepting
  everything it signed, including after a compromise; see
  `docs/operations.md`.
- **`--policy`** applies to receipts. With a database chain, which has no
  policy digest to compare, `praetore-verify journal --policy` fails with
  `INVALID_REQUEST` instead of reporting `policy_verified: true`.
- **Compatibility.** Chains without storage records or references are
  unchanged and verify as before. Verifiers older than this extension refuse
  chains that contain `record` or `database_head` lines (`INVALID_REQUEST`):
  fail closed. The limits of "Qué NO prueba" apply equally to the database
  chain: removing a record from the middle is detected only if the chain is
  not recomputed, or with an anchored head.

## Link

```
link = lowercase_hex( SHA-256(
    b"PRAETORE_JOURNAL_LINK_V1\0"     // 25 bytes, incluye el NUL final
 || u64_big_endian(seq)               // 8 bytes
 || ascii(prev)                       // 64 bytes: hex en minúsculas, no decodificado
 || ascii(evidence.context_hash)      // 64 bytes: hex tal como está en el recibo
 || ascii(evidence.attester_signature)// 128 bytes: hex tal como está en el recibo
))
```

Los campos se concatenan sin separadores. Un recibo sin `attester_signature`
hace fallar la cadena. El `link` de la última entrada es el `head` del
export.

## Verificación

Para cada línea, en orden:

1. La línea parsea según el formato.
2. `seq` es el esperado y `prev` coincide con el link anterior.
3. La firma Ed25519 del recibo es válida contra la clave de attester fijada.
4. El `evidence_id` no se repite.
5. Si se pasa `--policy`, el recibo registra ese digest de política
   (`Evidence::verify_policy`).
6. Al final, si se pasa `--expected-head`, el link de la última entrada es
   igual a ese valor (64 hex en minúsculas).

Cualquier fallo termina con exit distinto de 0, un código en stdout
(`JOURNAL_CHAIN_FAIL`, `JOURNAL_HEAD_MISMATCH`, `EVIDENCE_FAIL`, `AUTH_FAIL`,
`POLICY_MISMATCH`, `INVALID_REQUEST`, `INPUT_TOO_LARGE`) y un mensaje en
stderr que indica la entrada. El comportamiento es fail-closed.

## Límites

- 8 MiB por archivo.
- 4096 entradas.
- 64 KiB por recibo, que es el límite existente de `Evidence::from_json`.

## Qué NO prueba

El link es un SHA-256 **sin clave** y nadie firma el `head`. Quien tiene los
recibos firmados (sin necesitar ninguna llave privada) puede borrar, mover o
quitar recibos y recalcular `seq`, `prev` y el head; quien además tiene la
llave del atestador puede firmar recibos nuevos y armar cualquier cadena. Por
eso el head solo prueba algo si quedó **anclado fuera del control del
productor** (publicado en otro lugar) y el verificador lo compara con
`--expected-head`:

- **Borrado en el medio, reordenamiento, inserción de recibos firmados
  válidos:** sin `--expected-head` no se detectan si se recalcula la
  cadena; el verificador solo detecta ediciones de quien no la recalcula.
  Con un head anclado y `--expected-head`, la cadena recalculada da otro
  head y se rechaza (`JOURNAL_HEAD_MISMATCH`).
- **Truncado del final:** un prefijo de una cadena válida es una cadena
  válida. Solo se detecta con `--expected-head`.
- **Head publicado junto a la cadena:** los heads de `VERIFY.md` y del
  workflow de CI están en el mismo repositorio que las cadenas. Quien pueda
  cambiar una puede cambiar los otros: no son un ancla externa.
- **Fork / equivocación:** no se detecta. El productor puede entregar
  cadenas distintas a distintos auditores, cada una con su head.
- **Reemplazo completo:** con la llave del atestador se puede rehacer todo,
  incluidos los recibos. Lo único que no se puede sin esa llave es fabricar
  recibos, y eso lo impide la firma de cada recibo, no la cadena.
- Tampoco prueba que el export esté completo respecto del journal, ni que el
  orden registrado sea el orden real de las decisiones (el export desde el
  journal ordena por `created_at`), ni nada sobre la autorización vigente,
  la frescura o el estado de replay.

## Qué falta para que un tercero pruebe que no se borró nada

1. **Cadena calculada al escribir, no al exportar.** El link (o una hoja de
   un árbol de Merkle) se calcula en la misma transacción que inserta el
   recibo en el journal, con `seq` asignado por la base sin huecos.
2. **Head firmado.** El atestador (o la clave del gateway) firma
   periódicamente `(seq, head, timestamp)` con un dominio propio, y el
   verificador exige un head firmado contra la clave fijada. Hoy existe
   `--expected-head`, que compara contra un valor que el auditor consiguió
   por su cuenta; no hay head firmado.
3. **Mejor aún, ligar el `prev` dentro del recibo firmado**, para que la
   firma de cada recibo cubra su posición y no se pueda reencadenar sin la
   clave del atestador.
4. **Consistencia append-only entre heads** (árbol de Merkle estilo
   RFC 6962/9162, pruebas de consistencia e inclusión), para que un auditor
   con un head antiguo verifique que el nuevo lo extiende.
5. **Anclaje externo contra fork:** publicar los heads firmados fuera del
   control del operador (testigos que cofirman, un log de transparencia o un
   canal público) y que los auditores comparen heads entre sí.
6. **Liveness:** que la ausencia de un head nuevo dentro de un plazo sea en sí
   una falla visible; si no, el operador puede dejar de publicar.

Incluso con todo esto, la cadena solo cubre lo que entra al journal: no
prueba que una decisión tomada fuera del gateway quede registrada.
