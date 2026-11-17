# Propuesta: `praetore-mcp.receipt-view/1`

Estado: propuesta. Ningún lector valida este nombre. Los campos son los
que `receipt_view` ya escribe en `crates/praetore-mcp/src/dashboard.rs`.
No se extrae `verify_view`.

Un recibo que no parsea es un objeto con exactamente estas claves:

| Campo | Tipo | Origen |
|---|---|---|
| `location.file` | string | ruta del `*.jsonl` |
| `location.line` | número | número de línea, desde 1 |
| `parse_error` | string | error de `journal::parse_line` |
| `verified` | `false` | |
| `raw_text` | string | la línea, sin el salto |
| `raw` | objeto o `null` | JSON de la línea, o `null` si no es JSON |

Un recibo que parsea es un objeto con exactamente estas claves:

| Campo | Tipo |
|---|---|
| `location` | `{file, line}` como arriba |
| `parse_error` | `null` |
| `verified` | bool. `true` solo si no hay `order` y el primer chequeo no falla |
| `seq` | número o `null` (línea sin cadena) |
| `prev` | 64 hex o `null` |
| `order` | string o `null`. Problema de `seq`, `prev` o `evidence_id` repetido |
| `decided_at` | string o `null` |
| `server` | string o `null` |
| `tool` | string o `null` |
| `arguments` | el objeto de argumentos, o `{omitted, sha256, bytes}` si se omitieron |
| `decision` | `ALLOW`, `DENY` o `REQUIRE_APPROVAL` |
| `rule` | string (ids unidos por coma) o `null` |
| `decided_by` | objeto del recibo, o `null` en recibos anteriores al esquema v4 |
| `reason` | string |
| `mode` | `enforce`, `observe` o `null` |
| `evidence_id` | string |
| `approval` | string o `null` |
| `policy_digest` | string o `null` |
| `path_check` | objeto o `null` |
| `signatures` | ver abajo |
| `checks` | ver abajo |
| `raw` | el JSON de la línea |

`signatures`:

| Clave | Campos |
|---|---|
| `agent` | `agent_id`, `subject_key_hash`, `check` |
| `attester` | `key_id`, `check` |
| `authority` | `issuer`, `key_id`, `authority_id`, `check` |

`checks` tiene `shape`, `authority_subject`, `audience` y `mode`. Cada
`check` es `{status, error}`. `status` es `ok`, `fail` o `not_run`.
`error` es un string si `status` es `fail`, y `null` en los otros dos.

`not_run` sale en dos sitios distintos. Si la forma no es HighAssurance,
`shape` es `fail` y el resto `not_run`. Si `verify` no llega a correr
(pin ilegible, journal de aprobaciones ilegible), el objeto `verify` del
estado no es esta vista: es `{status: "error", error}` y cada `check` del
recibo queda `not_run` porque no hay resultado.

El objeto hermano `verify` (función `verify_view`, no este esquema) tiene,
cuando `verify` termina: `status` (`ok` o `fail`), `total`, `verified`,
`failed`, `failures`, `chained`, `unchained`, `head` (`{next_seq, prev}`
o `null`), `expected_head`, `attester_pin`, `issuer_pins` y `approval`
(`{decisions, executions, head}`). `failed` cuenta entradas de
`failures`, no líneas sin verificar: un `--expected-head` que no coincide
deja `verified == total` y `failed == 1`.
