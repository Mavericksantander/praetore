# SAF-13 · Anclaje opcional del head del journal (OpenTimestamps / RFC 3161) (propuesta)

Estado: **propuesta, solo documento.** No contiene código. Todas las decisiones
están marcadas **PROPUESTA**; ninguna está decidida.
Base: `origin/main` en `c86d16c` (#69, export encadenado del journal).
Nombre: sigue la convención `SAF-NN`. SAF-11 (#44) y SAF-12 (#58) están
tomados por PRs abiertos; el número SAF-13 es provisional.
Relación:
- [`journal-chain-jsonl.md`](journal-chain-jsonl.md) (implementado en #69):
  define el export y su `head`, y dice que el head "solo prueba algo si quedó
  anclado fuera del control del productor". Esta propuesta es ese anclaje.
- SAF-11 (#44, abierto): árbol de Merkle por tenant, checkpoints firmados con
  una llave de log y anclaje externo de cada checkpoint (su decisión 8).
  **SAF-13 no propone un log de transparencia.** Propone el componente de
  anclaje (sellar un hash con un tercero y verificarlo offline), aplicado hoy
  al head del export de #69 y reutilizable mañana por la decisión 8 de SAF-11
  sobre sus checkpoints. Ver §11.

## 1. Problema

El export de #69 produce un `head` (SHA-256 sin clave). Quien tiene los
recibos firmados puede borrar, truncar o reordenar y recalcular la cadena, y
el verificador la acepta salvo que se le pase `--expected-head` con un valor
que el auditor obtuvo por su cuenta. Hoy los únicos heads "fijados" están en
`examples/claude-code-hook/evidence/VERIFY.md` y en
`.github/workflows/assurance.yml`, en el mismo repositorio que las cadenas, así
que no son un ancla externa (lo dice el propio workflow).

Falta una forma estándar, barata y verificable por un tercero de responder:
**"este head existía en o antes del instante T"**, sin que el operador pueda
fabricar esa respuesta después.

## 2. Modelo de amenazas

Actores: el **operador** (controla el journal, el exportador y, en el peor
caso, la llave del atestador), el **auditor** (recibe exports y anclas, tiene
el pin del atestador y, para el anclaje, la raíz de confianza del sellador) y
el **sellador** (calendarios OpenTimestamps + Bitcoin, o una TSA RFC 3161).

Supuesto: el sellador no colude con el operador. Con RFC 3161 eso significa
confiar en la TSA y en su cadena de certificados; con OpenTimestamps, en que
no se reescriba la historia de Bitcoin (ver §4).

### Qué detecta el anclaje

Sea A un head anclado en el instante T_A para un export de `count_A`
entradas. Ante un export posterior E que el operador entrega al auditor:

| Ataque | ¿Lo detecta? | Condición |
|---|---|---|
| Truncar E por debajo de `count_A` | **sí** | E no tiene entrada `seq = count_A − 1`, o su link no es `head_A`. |
| Borrar, reordenar o insertar dentro del prefijo `[0, count_A)` y recalcular | **sí** | El link en `seq = count_A − 1` deja de ser `head_A` (verificación de prefijo, §6). |
| Recalcular la cadena completa, incluso con la llave del atestador | **sí, para el prefijo anclado** | Mismo motivo: el ancla fija el prefijo, no la llave. |
| Back-dating: afirmar que una cadena existía antes de lo que existió | **sí** | El sello prueba "existía antes de T", y no se puede obtener un sello con T en el pasado. |
| Presentar un head que nunca se ancló como si lo estuviera | **sí** | El sello no verifica contra el hash del statement. |

### Qué NO detecta

- **Eventos anteriores al primer ancla.** Si el operador manipuló el journal
  antes de anclar por primera vez, el ancla sella la versión ya manipulada.
- **Borrado o reescritura entre anclas.** Las entradas posteriores al último
  ancla (`seq ≥ count_A`) no están protegidas hasta el ancla siguiente. El
  operador puede reescribirlas, borrarlas o no exportarlas.
- **Retención de exports o de anclas (withholding).** Si el operador deja de
  anclar, o ancla y no entrega el ancla, el auditor no ve nada. El anclaje
  prueba existencia, no publicación ni completitud. Solo se detecta si el
  auditor exige un ancla por periodo y trata la ausencia como falla
  (liveness, §8), o si las anclas se publican donde el operador no controla
  (eso es SAF-11 / witnesses, no esta propuesta).
- **Fork / equivocación.** El operador puede anclar dos heads distintos y
  mostrar uno a cada auditor; un sello no impide sellar otra cosa. Solo lo
  detectan auditores que comparan entre sí o un log público (§11).
- **Recibos que nunca entraron al journal** (decisión tomada fuera del
  gateway o recibo no emitido). Igual que en #69 y SAF-11 §6.
- **Que el orden de la cadena sea el orden real.** El export desde el journal
  ordena por `(created_at, request_id)`; el ancla fija ese orden, no lo
  valida.
- **Que `export_time` u otros campos del statement digan la verdad.** El
  sello acota el tiempo **por arriba** (existía antes de T). El
  `export_time` declarado es solo una afirmación del operador.

### El intervalo de anclaje acota la exposición

Si se ancla cada Δ (o cada N recibos, lo que ocurra primero), lo máximo que el
operador puede reescribir sin ser detectado es lo producido desde el último
ancla: una ventana de a lo sumo Δ más la latencia del sellador. Con
OpenTimestamps esa latencia incluye la confirmación en Bitcoin (horas; §4), y
la precisión del sello es de horas, no de segundos. Con RFC 3161 la latencia
es de segundos y la precisión la declara la TSA (`accuracy` en `TSTInfo`).

## 3. Qué se ancla: el *head statement*

**PROPUESTA 1.** No se ancla el head pelado, sino un statement canónico que lo
contextualiza. Formato: JSON en una sola línea, claves en orden fijo, sin
espacios, terminado en `\n`, con un prefijo de dominio en el hash:

```text
{"v":1,"chain_format":"PRAETORE_JOURNAL_LINK_V1","tenant":"<uuid>|null",
 "entries":<count>,"last_seq":<count-1>,"head":"<64 hex>",
 "export_time":"<RFC 3339 UTC>","attester_pin":"<64 hex>"}

statement_digest = SHA-256( statement_bytes )
```

- `tenant` es `null` cuando el export viene de `--receipts-dir`.
- `attester_pin` liga el statement a la llave contra la que se verificó la
  cadena (un head con otro pin es otro statement).
- `last_seq` es redundante con `entries`; se incluye para que el verificador
  lo compruebe y para leerlo sin aritmética.
- Lo que sale hacia el sellador es **solo `statement_digest`** (32 bytes).
- El digest es SHA-256 directo de los bytes, sin prefijo de dominio, para que
  `openssl ts -verify -data` y `ots verify` funcionen sobre el archivo sin
  herramientas propias (§5). La separación de dominio la dan los campos `v` y
  `chain_format` dentro del propio statement. La alternativa con prefijo
  (`SHA-256("PRAETORE_HEAD_STATEMENT_V1\0" || bytes)`) es la pregunta Q4.

**PROPUESTA 2.** El atestador **firma** el statement (Ed25519, dominio propio
`PRAETORE_HEAD_STATEMENT_SIG_V1`), y se sella el digest del statement, no de
la firma. Motivo: la firma liga el head a la identidad del atestador; el sello
liga el statement a un instante. Son independientes: un ancla sin firma sigue
probando existencia en T, y una firma sin ancla no prueba nada temporal.
Limitación honesta: firmar exige que `journal-anchor` tenga acceso a la llave
del atestador (hoy `journal-export` solo usa el pin público). Si se prefiere no
ampliar ese acceso, el anclaje funciona sin firma y esa es la variante mínima
(ver pregunta abierta Q2). La firma de heads como mecanismo de log con llave
propia es SAF-11 decisión 7; aquí sería, a lo sumo, una firma del atestador
existente.

## 4. OpenTimestamps vs RFC 3161

| Criterio | OpenTimestamps (OTS) | RFC 3161 (TSA) |
|---|---|---|
| **Modelo de confianza** | Calendarios públicos agregan hashes en un árbol de Merkle y comprometen la raíz en una transacción de Bitcoin. La prueba final se ancla en un bloque; no hay que confiar en el calendario una vez confirmada, solo en la cadena de Bitcoin (proof-of-work). | Una TSA firma un `TSTInfo` (CMS `SignedData`) con `genTime`. Se confía en la TSA, en su política, y en la cadena de certificados hasta una raíz que el auditor fija. Una TSA comprometida o que colude puede emitir sellos con cualquier fecha. |
| **Latencia** | El calendario devuelve en segundos una prueba **pendiente** (solo vale como promesa del calendario). La prueba completa requiere que la transacción se confirme: típicamente horas; hay que "actualizar" (`upgrade`) el `.ots` después. | Segundos: una petición HTTP y la respuesta es definitiva. |
| **Precisión temporal** | De horas: el sello prueba "antes del bloque B", y el tiempo de bloque de Bitcoin tiene tolerancia de consenso (hasta ~2 h hacia adelante respecto del tiempo de red). Más el tiempo de agregación del calendario. | La que declare la TSA en `accuracy` (frecuentemente ≤ 1 s); garantizada solo por la política de la TSA. |
| **Verificación offline** | La ruta de hashes es offline. Falta el último paso: comprobar que la raíz resultante está en el header del bloque B. Requiere un nodo Bitcoin propio, un archivo de headers, o confiar en un explorador. Sin eso, la verificación es parcial. | Totalmente offline con el certificado de la TSA (o su raíz) fijado por el auditor. La comprobación de revocación (CRL/OCSP) sí requiere red, salvo que se embeba o se acepte no hacerla. |
| **Dependencias (Rust)** | Parseo del formato binario `.ots` y SHA-256/RIPEMD-160/Keccak según las operaciones de la prueba. Existe el crate `opentimestamps` (rust-opentimestamps); **no verificado** qué tan completo y mantenido está para verificar ni para `upgrade`. Sellar y actualizar requiere cliente HTTP hacia los calendarios. | DER/CMS/X.509 y la verificación de la firma de la TSA (RSA o ECDSA). Candidatos del ecosistema RustCrypto: `der`, `cms`, `x509-cert`, y `x509-tsp` para las estructuras de RFC 3161; `rsa`, `p256`. **No verificado** el estado de `x509-tsp` ni si cubre todo lo necesario. La alternativa sin código propio es `openssl ts -verify`. |
| **Costo** | Gratis para el usuario (los calendarios pagan las transacciones agregadas). | Hay TSAs gratuitas (p. ej. FreeTSA) y comerciales; las cualificadas eIDAS son de pago. Sin precios citados aquí. |
| **Disponibilidad** | Varios calendarios públicos independientes; el cliente puede enviar a varios y quedarse con cualquiera. Servicio voluntario, sin SLA. | Depende de la TSA elegida; las comerciales tienen SLA. Se pueden configurar varias. |
| **Validez a largo plazo (LTV)** | No depende de certificados que caducan. Depende de que SHA-256 y Bitcoin sigan siendo confiables; la prueba se puede re-sellar si un hash se debilita. | El certificado de la TSA caduca y puede revocarse. Pasado eso, verificar exige probar que el sello se emitió antes de la caducidad o revocación: re-sellado periódico (sellos de archivo, p. ej. *Evidence Record Syntax*, RFC 4998, o perfiles ETSI). Es el problema LTV clásico. |
| **Privacidad** | Solo sale el digest de 32 bytes (y el calendario además agrega un nonce). | Solo sale el digest en `MessageImprint`. La TSA ve la IP y el momento de la petición. |
| **Valor legal / eIDAS** | Ninguno reconocido como sello cualificado. Puede tener valor probatorio como evidencia técnica, según la jurisdicción. | Una TSA **cualificada** (Reglamento (UE) 910/2014, arts. 41–42, modificado por el Reglamento (UE) 2024/1183) da presunción de exactitud de la fecha y de integridad de los datos en la UE. Perfiles: ETSI EN 319 421 / EN 319 422. Una TSA no cualificada no da esa presunción. |

**PROPUESTA 3 (recomendación).** Un formato de ancla **enchufable** con dos
backends, y **RFC 3161 primero**:

- RFC 3161 es síncrono (el ancla queda completa al terminar el comando),
  verifica offline con un certificado fijado, encaja con el modelo de pines que
  ya usa `praetore-verify`, y es el que tiene peso legal en la UE si el piloto
  lo pide (TSA cualificada). Coincide con el orden que propone SAF-11 §7.
- OpenTimestamps como segundo backend, para quien no quiera confiar en una TSA:
  no depende de una autoridad ni de certificados que caducan, pero tiene
  latencia de horas, precisión de horas y una verificación offline que, sin
  headers de Bitcoin, es incompleta.
- Ambos a la vez es válido y recomendable para despliegues que lo quieran: una
  TSA comprometida no puede falsear el sello de Bitcoin, y el sello de Bitcoin
  no cubre el valor legal. El verificador informa de cada uno por separado.

## 5. Formatos de archivo

**PROPUESTA 4.** Todo vive junto al export, con el mismo nombre base. Ningún
comando sobrescribe un archivo existente (igual que `journal-export`).

```text
journal-chain.jsonl                 # export de #69, sin cambios
journal-chain.head.json             # head statement canónico (§3), bytes exactos
journal-chain.head.sig              # opcional: firma Ed25519 del atestador, 128 hex + \n
journal-chain.head.tsr              # RFC 3161: TimeStampResp DER completo (status + token)
journal-chain.head.ots              # OpenTimestamps: prueba serializada sobre statement_digest
```

- El `.tsr` es la respuesta DER tal cual (`application/timestamp-reply`,
  RFC 3161 §3.4). Se guarda la respuesta completa, no solo el token, para que
  `openssl ts -verify -in journal-chain.head.tsr` funcione también.
- El `MessageImprint` es `SHA-256` + `statement_digest` (§3), de modo que
  `openssl ts -verify -data journal-chain.head.json -in journal-chain.head.tsr`
  y `ots verify` sobre `journal-chain.head.json` funcionan sin herramientas
  propias.
- Petición RFC 3161: `certReq = true` (para que el token traiga el
  certificado del firmante) y `nonce` aleatorio, que el cliente comprueba en
  la respuesta. `reqPolicy` solo si la TSA lo exige.
- RFC 5816 permite `ESSCertIDv2` (identificador del certificado con SHA-256 en
  vez de SHA-1). El verificador acepta ambos y, si hay `ESSCertIDv2`, lo
  comprueba.
- El `.ots` empieza pendiente (atestación del calendario) y se actualiza in
  situ a la prueba con atestación de Bitcoin. Es la única excepción a "no
  sobrescribir": se propone escribir el `.ots` actualizado en un archivo
  nuevo (`.head.ots` → `.head.ots.tmp` → rename atómico) y solo si la prueba
  nueva contiene a la vieja (pregunta Q5).

Varios anclajes de una misma cadena a lo largo del tiempo (§6) usan un sufijo
de `seq`: `journal-chain.head-000127.json`, `.head-000127.tsr`, etc.

## 6. UX del CLI y del verificador

**PROPUESTA 5.** Un subcomando nuevo en `praetore` (productor, con red) y una
opción nueva en `praetore-verify journal` (verificador, **sin red**).

```text
praetore journal-anchor --journal journal-chain.jsonl --attester-pin HEX_FILE \
    [--tenant UUID] [--sign-with-attester KEY_SOURCE] \
    (--tsa-url URL [--tsa-url URL ...] | --ots-calendar URL [...] | --config PATH)
  → verifica la cadena (misma función que el verificador), escribe .head.json,
    pide los sellos, verifica la respuesta y escribe .tsr / .ots.

praetore journal-anchor --upgrade journal-chain.head.ots
  → solo OTS: pide al calendario la prueba completa cuando ya hay bloque.

praetore-verify journal --journal journal-chain.jsonl --attester-pin HEX_FILE \
    --anchor journal-chain.head.json [--anchor ...] \
    [--tsa-cert PEM ...] [--btc-headers FILE] [--not-before RFC3339] [--format json|text]
```

Reglas del verificador:

1. Verifica la cadena como hoy (#69).
2. Para cada `--anchor S`: parsea S (exacto, canónico, campos conocidos);
   comprueba que el link de la entrada `seq = S.last_seq` de la cadena es
   `S.head` y que `S.attester_pin` coincide con el pin pasado. Esto es la
   **verificación de prefijo**: la cadena actual extiende el head anclado. No
   exige que `S.last_seq` sea la última entrada.
3. Si hay `S.sig`, la verifica contra el pin del atestador.
4. Busca `.tsr` y/o `.ots` junto a S. Para `.tsr`: estado `granted`, firma CMS
   válida, `MessageImprint` igual al digest de S, certificado firmante con
   EKU `id-kp-timeStamping` crítico (RFC 3161 §2.3) y que encadena a uno de
   los `--tsa-cert` fijados. Para `.ots`: ruta de hashes desde el digest hasta
   una atestación de Bitcoin, y comprobación de la raíz contra
   `--btc-headers` si se pasa.
5. Sin red. No consulta CRL ni OCSP; si el token trae datos de revocación
   embebidos, se informa pero no se exige (pregunta Q6).

Salida (se agrega a la de hoy):

```json
"anchors": [
  {"statement": "journal-chain.head-000127.json", "last_seq": 127,
   "prefix_verified": true, "signature": "verified|absent",
   "rfc3161": {"status": "verified", "gen_time": "...", "tsa": "<subject>"},
   "ots": {"status": "pending|verified_path_only|verified", "block_height": 0}}
]
```

- Cualquier fallo de prefijo, firma o sello presentes es **fail-closed**, con
  códigos nuevos: `JOURNAL_ANCHOR_MISMATCH` (prefijo o digest),
  `ANCHOR_SIGNATURE_FAIL`, `ANCHOR_TIMESTAMP_FAIL`, `ANCHOR_UNTRUSTED_TSA`.
- Un `.ots` **pendiente** o verificado sin headers no es un fallo, pero se
  informa con un estado distinto y nunca se presenta como "verified". Con
  `--require-anchor-complete` se vuelve fallo.
- `--not-before T`: falla si algún sello es posterior a T (útil para exigir que
  el auditor recibió un ancla dentro de un plazo).
- `expected_head_verified` existente no cambia de significado.

**Límite actual que afecta al diseño.** `MAX_CHAIN_ENTRIES = 4096` y el export
siempre empieza en `seq = 0`. Un journal más grande no cabe en un export, y la
verificación de prefijo necesita la cadena desde el principio. Hasta que exista
un export por segmentos (con el `prev` del primer segmento igual al head del
anterior) o el árbol de SAF-11, el anclaje solo sirve para journals de hasta
4096 recibos por tenant (pregunta Q3).

## 7. Modos de falla

**PROPUESTA 6.** El anclaje **nunca** está en el camino de autorización.

- `journal-anchor` es un proceso aparte (CLI o tarea programada). El gateway,
  `praetore-mcp` y el motor no lo llaman ni esperan por él. Una TSA caída no
  bloquea ni demora ninguna decisión: fail-open **para las operaciones**.
- Pero la falta de ancla **queda registrada**: si ningún backend responde,
  `journal-anchor` escribe igual el `.head.json` y un
  `.head.gap.json` (`{"statement_digest":..., "attempted_at":..., "backends":[...], "error":...}`),
  sale con código distinto de 0 y lo emite como evento de observabilidad. El
  siguiente ancla exitoso cubre el prefijo (la verificación de prefijo hace
  que un ancla posterior proteja también lo que quedó sin anclar antes), pero
  la ventana de exposición se amplió y el hueco es visible.
- Un `.gap.json` no prueba nada criptográficamente (lo escribe el operador);
  sirve para la operación honesta, no contra un operador malicioso.
- TSA que responde con error, `nonce` distinto, imprint distinto o certificado
  no fijado: se trata como fallo de ese backend, se prueba el siguiente.
- OTS: calendario caído → probar otro; prueba pendiente que no se completa en
  X horas → aviso (no error del verificador, que solo informa el estado).

## 8. Configuración

**PROPUESTA 7.** Desactivado por defecto. Sin configuración, nada cambia y
ningún binario hace tráfico de red nuevo.

```toml
# praetore-anchor.toml (ejemplo; nombres provisionales)
[anchor]
enabled = false
every_receipts = 1000        # o
every_seconds  = 3600        # lo que ocurra primero
sign_statement = false

[[anchor.rfc3161]]
url = "https://tsa.example/tsr"
cert_pin = "tsa-chain.pem"   # el productor también verifica antes de guardar

[[anchor.ots]]
calendar = "https://<calendario>"   # se proponen al menos dos
```

- Las URLs no se incluyen por defecto: el despliegue elige su TSA o sus
  calendarios. Los ejemplos de docs usan servicios públicos, marcados como
  tales.
- **Liveness:** el auditor, no PRÆTORE, define el plazo máximo entre anclas
  (`--not-before`). Que el producto lo imponga del lado del operador no sirve
  contra un operador malicioso.

## 9. Dependencias y la restricción del verificador offline

- `praetore-verify` hoy depende solo de `praetore-core`, `praetore-receipt`,
  `serde`, `serde_json`, `hex` y `time`. El job `verifier-features` de
  `assurance.yml` comprueba (con default y `--all-features`) que no habilite
  `praetore-receipt/signing`, y el job `audit` revisa advisories.
- **PROPUESTA 8.**
  - El código de red (cliente HTTP hacia TSA y calendarios) vive **solo** en
    `praetore-cli` (`journal-anchor`) o en un crate nuevo `praetore-anchor`
    con feature `client`. Nunca en `praetore-verify`.
  - El parseo y la verificación (DER/CMS/X.509, prueba OTS) van en
    `praetore-anchor` sin feature de red, y `praetore-verify` lo usa detrás de
    una feature `anchor`. Se propone que esté **activada por defecto** en el
    binario publicado (si no, nadie lo verifica), y que el CI agregue un
    chequeo análogo al de `signing`: `cargo tree -p praetore-verify
    --all-features` no debe contener crates de cliente HTTP ni TLS
    (`reqwest`, `hyper`, `ureq`, `rustls`, `native-tls`, `openssl-sys`).
  - El parseo de DER y de `.ots` es código que recibe entrada de terceros:
    límites de tamaño (p. ej. 64 KiB por `.tsr`/`.ots`) y un target de fuzz
    nuevo (`anchor_verify`) en `fuzz.yml`.
- Alternativa más conservadora: `praetore-verify` no verifica sellos, solo el
  statement y el prefijo, y documenta `openssl ts -verify` / `ots verify`
  como paso externo. Menos código, menos superficie, peor UX (pregunta Q1).

## 10. Tests y plan de aceptación

Como en SAF-10/SAF-11: primero los tests, después la implementación.

**Unitarios / propiedad (`praetore-anchor`, `praetore-core`):**
- El statement es canónico: serializar → parsear → serializar es idéntico;
  claves fuera de orden, campos extra, espacios o `\r` se rechazan.
- Verificación de prefijo: para toda cadena válida y todo `k < n`, el
  statement del prefijo `k` verifica contra la cadena completa; borrar,
  reordenar o truncar cualquier entrada con `seq ≤ k` y recalcular hace fallar
  ese statement (`JOURNAL_ANCHOR_MISMATCH`).
- Truncar a menos de `last_seq + 1` entradas falla.
- `attester_pin` distinto falla.

**RFC 3161 (fixtures DER versionados, sin red en CI):**
- Un `.tsr` real de una TSA de prueba (y uno generado con `openssl ts` y una
  CA de test, marcado DEMO/TEST-ONLY) verifica con su cert fijado.
- Falla: un byte cambiado en el token, imprint de otro statement, cert no
  fijado, EKU ausente o no crítico, `status` ≠ granted, `ESSCertIDv2` que no
  coincide.
- Interoperabilidad: el mismo `.tsr` verifica con `openssl ts -verify -data
  journal-chain.head.json` (job de CI que solo usa openssl).

**OTS (fixtures versionados):**
- Prueba pendiente → estado `pending`, nunca `verified`.
- Prueba completa + header del bloque en `--btc-headers` → `verified`; sin
  headers → `verified_path_only`; header de otro bloque → falla.
- Un byte cambiado en la ruta → falla.

**Integración / aceptación:**
1. Con los sets `03`, `04`, `05` de `examples/claude-code-hook/evidence/`,
   publicar un `.head.json` + `.tsr` por set y un job de CI que los verifique
   offline. El sello sí es externo al repo (lo emite la TSA), a diferencia de
   los heads de `VERIFY.md`.
2. El job demuestra el valor: una copia con un recibo borrado y la cadena
   recalculada pasa `praetore-verify journal` sin `--anchor` y **falla** con
   `--anchor`.
3. Con la TSA inalcanzable, `journal-anchor` escribe `.gap.json`, sale ≠ 0, y
   un test del gateway confirma que la autorización no se ve afectada.
4. `cargo tree` de `praetore-verify` sin crates de red (§9).

## 11. Relación con SAF-11 y alternativas consideradas

**SAF-11 (#44).** SAF-11 resuelve completitud con un árbol de Merkle por tenant,
checkpoints firmados por una llave de log y pruebas de inclusión y
consistencia; su decisión 8 deja el anclaje externo como "configurable: RFC
3161 y/o witnesses". SAF-13:
- **no** duplica el árbol, los checkpoints ni las pruebas de inclusión;
- especifica el backend de anclaje (formatos, verificación offline, modos de
  falla, dependencias) que la decisión 8 de SAF-11 necesitaría;
- lo aplica ya al head de #69, que existe hoy, como paso intermedio. La
  verificación de prefijo de §6 es un sustituto lineal y limitado (4096
  entradas, cadena completa) de las pruebas de consistencia de SAF-11.
- Si SAF-11 se aprueba, el statement de §3 se reemplaza por su checkpoint y
  el resto (sellado, `.tsr`/`.ots`, verificador) se reutiliza.

**Alternativas:**

| Alternativa | A favor | En contra |
|---|---|---|
| Log de transparencia público (Sigstore Rekor) | Además de tiempo, da **publicación**: detecta fork si los auditores consultan el log, y el log tiene sus propias pruebas de inclusión y consistencia. | Publica el hash en un log público operado por terceros (aunque solo sea el hash). La verificación offline necesita guardar la prueba de inclusión y la clave del log; la API y los tipos de entrada de Rekor cambian entre versiones (**no verificado** el estado actual). Dependencia operativa de un servicio externo. |
| Witnessing por git (commit del statement en un repo de un tercero o en un repo público con historia protegida) | Simple, sin dependencias nuevas, publicación visible. | El tiempo lo da el servidor git (no es una prueba criptográfica de tiempo); quien controla el repo puede reescribirlo; los heads de hoy ya están en git y no sirven como ancla (§1). Útil solo si el repo lo controla el auditor. |
| Witnesses que cofirman (estilo transparency-dev / C2SP signed notes) | La mejor defensa contra fork: varios terceros cofirman el mismo head y se niegan a cofirmar uno inconsistente. | Requiere terceros dispuestos a operar witnesses y un formato de checkpoint; es el terreno de SAF-11 (decisiones 7 y 8). |
| Entrega directa del head al auditor (correo, ticket) | Cero dependencias. | Sin tiempo verificable; depende de que el auditor lo guarde; no escala. Es lo que hoy permite `--expected-head`. |
| No hacer nada hasta SAF-11 | Sin trabajo intermedio. | La limitación del README sigue igual y #69 no aporta garantía frente a un adversario. |

## 12. Pasos por fases

1. **Fase 0 (este documento).** Aprobación de las decisiones 1–8 y respuestas
   a §13.
2. **Fase 1.** Statement canónico + verificación de prefijo + `--anchor` en
   `praetore-verify`, sin sellos todavía (el statement se entrega al auditor
   fuera de banda). Tests de propiedad primero. Ya acota el valor de
   `--expected-head` a un formato con contexto.
3. **Fase 2.** Backend RFC 3161: `praetore journal-anchor --tsa-url`, `.tsr`,
   verificación offline con cert fijado, fixtures, job de interoperabilidad con
   `openssl ts`, chequeo `cargo tree` sin red, target de fuzz.
4. **Fase 3.** Anclaje de los sets de evidencia del hook en CI (§10.1–2).
5. **Fase 4 (opcional).** Backend OpenTimestamps (`--ots-calendar`,
   `--upgrade`, `--btc-headers`).
6. **Fase 5.** Si SAF-11 avanza, reemplazar el statement por el checkpoint de
   SAF-11 y retirar la verificación de prefijo a favor de sus pruebas de
   consistencia.

## 13. Preguntas abiertas para el fundador

- **Q1.** ¿`praetore-verify` verifica los sellos él mismo (más dependencias
  DER/CMS, feature `anchor`) o delega en `openssl ts` / `ots` y solo verifica
  statement y prefijo?
- **Q2.** ¿El atestador firma el statement (exige que `journal-anchor` acceda
  a la llave del atestador) o basta el sello sin firma?
- **Q3.** ¿Se sube `MAX_CHAIN_ENTRIES` o se diseña un export por segmentos
  antes de que el anclaje sea útil para tenants con más de 4096 recibos? ¿O se
  espera a SAF-11?
- **Q4.** ¿Digest del statement como SHA-256 directo de los bytes (se
  propone, para interoperar con `openssl ts -verify -data` y `ots verify`) o
  con prefijo de dominio propio (más separación, pero exige herramienta
  propia para verificar)?
- **Q5.** OTS: ¿se acepta reescribir el `.ots` al actualizarlo (rename
  atómico), como única excepción a "nunca sobrescribir"?
- **Q6.** ¿Se exige comprobación de revocación del certificado de la TSA? Si
  sí, el verificador deja de ser offline o hay que embeber CRL/OCSP en la
  evidencia.
- **Q7.** ¿Hace falta una TSA **cualificada** eIDAS para el piloto, o basta
  una TSA no cualificada? Afecta costo y proveedor.
- **Q8.** ¿Intervalo por defecto (se sugiere cada 1000 recibos o cada hora,
  como orden de magnitud) y quién lo opera en el modo local (`praetore-mcp`)?
- **Q9.** ¿Los statements y sellos se publican (por ejemplo, en el repo de
  evidencia o un canal público) o solo se entregan al auditor de cada tenant?
  Publicarlos es lo único de esta propuesta que ayuda contra fork.

## 14. Referencias

- RFC 3161, *Internet X.509 PKI Time-Stamp Protocol (TSP)*, 2001.
  Estructuras `TimeStampReq`, `TimeStampResp`, `TSTInfo`; EKU
  `id-kp-timeStamping` (§2.3); transporte HTTP (§3.4).
- RFC 5816, *ESSCertIDv2 Update for RFC 3161*, 2010.
- RFC 5652, *Cryptographic Message Syntax (CMS)* (el token es un `SignedData`).
- RFC 4998, *Evidence Record Syntax (ERS)* (re-sellado para validez a largo
  plazo).
- RFC 6962 / RFC 9162, *Certificate Transparency* (referencia de SAF-11).
- OpenTimestamps: https://opentimestamps.org y el repositorio
  https://github.com/opentimestamps/opentimestamps-client (formato `.ots`,
  `stamp` / `upgrade` / `verify`). Los detalles del formato binario no se
  reproducen aquí; se tomarán de la implementación de referencia.
- Reglamento (UE) 910/2014 (eIDAS), arts. 41–42, y Reglamento (UE)
  2024/1183 (eIDAS 2). ETSI EN 319 421 y EN 319 422.
- Sigstore Rekor: https://docs.sigstore.dev (alternativa, §11).
- C2SP *signed note* / *tlog-witness*: https://c2sp.org (alternativa, §11).
