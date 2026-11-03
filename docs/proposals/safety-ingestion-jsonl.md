# Ingesta post-hoc de acciones de seguridad (G1, SAF-09.5): formato v2

**Estado: implementado** (rama `feat/g1-safety-ingestion`, 2-nov-2026),
transporte v1 local (socket Unix). Los límites de "Qué NO prueba" siguen
vigentes.

Un ejecutor de un sistema AI-enabled ejecuta una acción de seguridad (por
ejemplo `safety:halt` o `safety:stop_all`) **sin esperar a PRÆTORE**. Después,
si quiere, la reporta. La ingesta está aislada del camino de decisión: proceso
propio (`praetore-safety-ingest`), rol de base de datos propio
(`praetore_safety_ingest`), llave propia (la llave de ingesta) y socket propio.
Ningún motor, gateway, gate ni hook lee estos registros.

- Tipos, reglas y verificador: `praetore_core::safety_ingest`. El ingestor,
  el exportador y el verificador usan el mismo código.
- Cliente: crate `praetore-safety-client` (`SafetyClient::send`): un
  `sendto` no bloqueante por evento, sin reintentos; si falla, el evento se
  descarta localmente, se cuenta y se devuelve un error que el ejecutor
  puede ignorar.
- Ingestor: `praetore-safety-ingest` (configuración en `docs/operations.md`).
- Almacenamiento: `praetore.safety_records` (migración 0016).
- Export: `praetore journal-export --safety --tenant UUID --source ID
  --ingest-pin HEX_FILE [--ingest-pin ...] [--source-pins JSONL] --output
  NUEVO`. Verifica la cadena antes de escribir y nunca sobrescribe.
- Verificador: `praetore-verify safety-journal --journal JSONL --ingest-pin
  HEX_FILE [--ingest-pin ...] [--source-pins JSONL] [--expected-head HEX]
  [--format json|text]`.

## Dominios y llaves

| Uso | Dominio |
| --- | --- |
| Firma de un evento (llave de la fuente) | `PRAETORE_SAFETY_EVENT_V1\0` |
| Hash y firma de un registro (llave de ingesta) | `PRAETORE_SAFETY_RECORD_V1\0` |
| Key id de una fuente | `PRAETORE_SAFETY_SOURCE_KEY_V1\0ed25519\0` |
| Key id de la llave de ingesta | `PRAETORE_SAFETY_INGEST_KEY_V1\0ed25519\0` |

Ningún dominio del repositorio es prefijo de otro (el test
`no_domain_is_a_prefix_of_another` de `crates/praetore-core/tests/safety_namespace.rs`
los recorre todos, estos incluidos). Al arrancar, el ingestor exige que la
llave de ingesta, la llave del namespace, la llave del atestador y cada llave
de fuente sean distintas dos a dos (`ensure_distinct_keys`), sin flag para
saltarlo.

## Evento (lo que firma y envía la fuente)

Un objeto JSON con exactamente:

- `schema_version`: `2` (la versión 1, sin `source_epoch`, se rechaza).
- `source_id`: 1 a 64 bytes de `a-z 0-9 . _ -`, empieza con letra o dígito.
- `source_key_id`: `hex(SHA-256("PRAETORE_SAFETY_SOURCE_KEY_V1\0ed25519\0" || clave pública))`.
- `source_epoch`: entero de 1 a 2^53 - 1, la ejecución de la fuente. Sube
  en cada arranque de la fuente (`praetore_safety_client::EpochFile`, que lo
  guarda con `fsync` antes del primer evento y falla cerrado si no puede:
  nunca vuelve a 1).
- `source_seq`: entero de 1 a 2^53 - 1, monótono dentro de un epoch, sin
  huecos; empieza en 1 en cada epoch.
- `action`: el nombre crudo. Se registra aunque no sea un nombre válido.
- `occurred_at`: RFC 3339 en UTC, **reloj de la fuente**.
- `params` (opcional, nunca vacío): hasta 16 claves `[a-z0-9_]{1,64}`, cada
  valor un string de hasta 256 bytes, un entero seguro o un booleano.
- `post_hoc`: siempre `true` (la acción ya se ejecutó).
- `signature`: `hex(Ed25519("PRAETORE_SAFETY_EVENT_V1\0" || JSON canónico de
  todos los demás campos))`.

El mensaje en el socket puede ser cualquier codificación JSON estricta de ese
objeto (sin claves duplicadas), de hasta 8 KiB; uno más largo se registra
como `rejected` (`too_large`), y el ingestor lee como máximo 64 KiB + 1 bytes
de un datagrama. Un datagrama vacío es la sonda con la que un segundo
ingestor comprueba si el socket está vivo: no es un evento y no se registra. La firma y el `event_hash =
hex(SHA-256("PRAETORE_SAFETY_EVENT_V1\0" || payload firmado))` cubren la forma
canónica, así que dos codificaciones del mismo evento tienen el mismo hash.

## Registro (lo que guarda el ingestor)

Cada registro es el JSON canónico (claves ordenadas, sin espacios) de un
objeto con `schema_version` (2), `record_id`, `tenant_id`, `chain`,
`chain_seq`, `prev_record_hash`, `recorded_at` (RFC 3339 UTC, reloj del
ingestor), `status`, `key_id` (la llave de ingesta), `record_hash`,
`signature` y los campos opcionales que exige su `status` (abajo). En una
cadena de fuente, cada registro firma además `high_water`: el high-water de
`source_seq` después de él. El ingester reanuda desde ese valor firmado (la
columna `high_water` de la tabla debe coincidir; lo exige el trigger) y el
verificador comprueba que coincide con el que calcula. En `_unattributed` no
va. Cada registro de una cadena de fuente firma también `source_epoch`, el
epoch de su segmento (en un registro con evento, el del evento); la columna
`source_epoch` debe coincidir (trigger, migración 0017). Un evento verificado con `occurred_at` a más de
`PRAETORE_SAFETY_MAX_CLOCK_SKEW_SECONDS` del reloj del ingester lleva
`clock_skew_seconds` (`occurred_at - recorded_at`). El payload
es todo salvo `record_hash` y `signature`, en JSON canónico; `record_hash =
hex(SHA-256("PRAETORE_SAFETY_RECORD_V1\0" || payload))` y `signature =
hex(Ed25519("PRAETORE_SAFETY_RECORD_V1\0" || payload))`. Cualquier otra
codificación del mismo registro se rechaza.

**Cadena.** Hay una cadena por `(tenant_id, chain)`. `chain` es el
`source_id` de la fuente, o `_unattributed` para todo lo que no se puede
atribuir a una fuente fijada. `chain_seq` empieza en 0 y sube de 1 en 1;
`prev_record_hash` es el `record_hash` del registro anterior (64 ceros en el
primero). Como ambos campos están **dentro del payload firmado**, reencadenar
exige la llave de ingesta (a diferencia del link sin clave de
`journal-chain-jsonl.md`).

**Epochs (segmentos).** Una cadena de fuente es una secuencia de segmentos,
uno por `source_epoch`, en orden creciente. Un evento con un epoch mayor que
el de la cadena abre un segmento nuevo: su high-water empieza en 0, así que
una fuente reiniciada que vuelve a `source_seq` 1 registra `accepted` (no
`conflict`), y un primer evento con `source_seq` > 1 registra antes la
pérdida `1..=seq-1` de ese epoch. Lo que la fuente no envió al final del
epoch anterior no es visible. `duplicate`, `conflict` y `late` se buscan
dentro del epoch. Un evento de un epoch menor se registra como `rejected`
(`stale_epoch`) en `_unattributed`; uno más de `PRAETORE_SAFETY_MAX_SEQ_JUMP`
por encima, como `rejected` (`epoch_jump_too_large`). Ninguno de los dos
cambia la cadena de la fuente.

| `status` | Cadena | Significado y campos |
| --- | --- | --- |
| `accepted` | fuente | evento verificado, `source_seq` siguiente, nombre declarado en el manifiesto |
| `undeclared` | fuente | igual, nombre válido pero no declarado |
| `invalid_name` | fuente | igual, `action` falla `SafetyActionName::parse`; `reason` es el código (`empty`, `too_long`, `not_printable_ascii`, `missing_prefix`, `invalid_name_start`) y `detail` el error escapado |
| `duplicate` | fuente | `source_seq` ya registrado con el **mismo** `event_hash`; `original_record_hash` apunta al primero |
| `conflict` | fuente | `source_seq` ya registrado con **otro** `event_hash`; `original_record_hash` apunta al primero |
| `late` | fuente | `source_seq` que antes se registró como perdido |
| `loss` (`source_seq_gap`) | fuente | `lost_from..=lost_to` nunca llegaron; va justo antes del evento que reveló el hueco |
| `loss` (`queue_overflow`, `storage_error`) | `_unattributed` | `dropped` mensajes no se leyeron (cola llena) o no se pudieron guardar (base caída) |
| `rejected` | `_unattributed` | entrada que no verificó; `reason` (`too_large`, `malformed`, `not_post_hoc`, `unknown_source`, `key_mismatch`, `signature_invalid`, `seq_jump_too_large`, `stale_epoch`, `epoch_jump_too_large`), `detail` y `raw`. `seq_jump_too_large` es un evento verificado cuyo `source_seq` está más de `PRAETORE_SAFETY_MAX_SEQ_JUMP` por encima del high-water de su cadena: queda aquí y la cadena de la fuente no cambia |

Todo registro con evento lleva `event` (el evento completo, con su firma),
`event_hash`, `name_class` (`declared`, `undeclared`, `invalid_name`) y
`namespace_policy_digest` (el `policy_digest` del manifiesto con el que se
clasificó el nombre). `raw` lleva `escaped` (los primeros 512 bytes, ASCII
imprimible: `\\` para la barra invertida y `\xNN` para cualquier otro byte),
`len`, `sha256` de la entrada completa y `truncated`. Nada se descarta en
silencio: lo que no verifica se guarda como `rejected`.

**Duplicados (decisión).** Un reenvío del mismo evento no es idempotente:
se guarda como `duplicate`, para que un replay sea visible en la cadena. No
mueve el `source_seq` esperado. Un evento distinto con un `source_seq` ya
usado se guarda como `conflict` (dos eventos firmados por la misma fuente
con la misma posición: un error o una llave comprometida).

## Export

Un archivo UTF-8, un registro por línea, cada línea (también la última)
terminada en `\n`, sin líneas vacías. Las líneas son el `record_json`
guardado, en orden de `chain_seq`. El head es el `record_hash` de la última
línea. Límites: 64 MiB y 200 000 registros por archivo, 64 KiB por registro.

## Verificación (`verify_safety_chain`)

Para cada línea, en orden, fail-closed:

1. Es la codificación canónica de un registro válido para su `status`, y su
   `event_hash` es el hash de su `event`.
2. `key_id` es el de una de las llaves de ingesta fijadas, `record_hash`
   coincide y la firma verifica.
3. `chain` y `tenant_id` son los de la primera línea; `chain_seq` es el
   número de línea; `prev_record_hash` es el `record_hash` anterior;
   `record_id` no se repite.
4. Epochs (cadena de fuente): `source_epoch` nunca baja; cuando sube empieza
   un segmento nuevo (high-water 0, sin referencias a segmentos anteriores),
   y no puede subir entre un `loss` y el evento que lo sigue.
   Continuidad de `source_seq` dentro del segmento: cada `accepted`,
   `undeclared` o `invalid_name` es el siguiente; un hueco solo puede estar
   cubierto por un `loss` que empieza en el siguiente y al que sigue el
   evento que lo reveló; `duplicate`/`conflict` nombran al primer registro de
   su `source_seq` con el mismo/otro hash; `late` rellena un `source_seq`
   perdido que no tenía evento. La cadena `_unattributed` solo tiene
   `rejected` y pérdidas internas.
5. Con `--source-pins`, la firma de cada evento contra la llave de su fuente.
6. Con `--expected-head`, el head es igual a ese valor.

Reporta la cantidad de `accepted`, `undeclared`, `invalid_name`,
`duplicate`, `conflict`, `late`, `rejected`, `loss`, eventos perdidos y
mensajes descartados, más la cantidad de epochs, el epoch final y su
high-water. Códigos: `SAFETY_CHAIN_FAIL`, `SAFETY_SEQUENCE_FAIL`,
`EVIDENCE_FAIL`, `AUTH_FAIL`, `SAFETY_EVENT_SIGNATURE_INVALID`,
`JOURNAL_HEAD_MISMATCH`, `INVALID_REQUEST`, `INPUT_TOO_LARGE`.

## Qué prueba y qué NO prueba

Prueba que el poseedor de la llave de ingesta registró estos registros en
este orden, y (con `--source-pins`) que cada evento lo firmó la llave de su
fuente. No prueba:

- **Que la acción ocurrió, ni cuándo.** El evento es post-hoc y `occurred_at`
  es el reloj de la fuente. PRÆTORE no decidió ni autorizó nada.
- **Que no hubo otras acciones.** Un ejecutor puede no reportar; un evento
  descartado por el cliente aparece solo como hueco cuando llega el siguiente
  evento de esa fuente (no hay hueco visible si nunca llega otro).
- **Nada si la llave de una fuente está comprometida.** Quien la tiene firma
  eventos válidos para esa fuente (verían `conflict` si reusa posiciones).
- **Completitud o truncado.** Un prefijo de una cadena válida es válido: solo
  `--expected-head` con un head anclado fuera del control del operador lo
  detecta. Con la llave de ingesta se puede rehacer una cadena entera.
- **Integridad de `_unattributed`.** Cualquiera con acceso al socket puede
  llenarla de `rejected`; los permisos del socket (0600, o 0660 con un grupo)
  lo limitan.

## Futuro

- Transporte de red (HTTP con mTLS) entre hosts.
- Rotación de la llave de ingesta con verificación de la transición (hoy se
  fijan las dos llaves con `--ingest-pin` repetido).
- Export incremental y anclaje externo del head (SAF-13).
