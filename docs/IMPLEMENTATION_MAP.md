# Mapa de implementación

Observación del 2026-11-19. Base leída en esta pasada, después de
`git fetch origin main`:

| Campo | Valor |
|---|---|
| `git rev-parse origin/main` | `230f4d55ad5cc2789a6beb7db53fbc7f31cd1ec1` |
| `git log -1` | `Merge pull request #158 from Mavericksantander/feat/approval-delegation` |
| Fecha del merge | 2026-11-18 21:10:24 -0300 |
| `workspace.package.version` | `0.3.6` (`Cargo.toml`) |

`git merge-base --is-ancestor` de ese SHA contra `origin/main` salió 0.
El mismo SHA es el merge que devolvió `gh pr view 158`.

Este archivo no está en `230f4d55`. En esta pasada
`git cat-file -e 230f4d55ad5cc2789a6beb7db53fbc7f31cd1ec1:docs/IMPLEMENTATION_MAP.md`
salió 128:

`fatal: path 'docs/IMPLEMENTATION_MAP.md' exists on disk, but not in '230f4d55ad5cc2789a6beb7db53fbc7f31cd1ec1'`.

`git log --oneline 230f4d55ad5cc2789a6beb7db53fbc7f31cd1ec1 -- docs/IMPLEMENTATION_MAP.md`
no imprimió commits (exit 0). `git grep -l IMPLEMENTATION_MAP 230f4d55ad5cc2789a6beb7db53fbc7f31cd1ec1`
salió 1. La columna «antes» es **sin nivel** porque ese commit no tiene
un número escrito para estas filas. Los de «ahora» salen de los comandos
y de los runs citados abajo.

## Escala

La del BRIEF, sin recodificarla:

| Nivel | Significado |
|---|---|
| 1 | implementado y verificado |
| 2 | implementado, poco probado |
| 3 | parcial |
| 4 | diseñado, no implementado |
| 5 | limitación conocida |
| 6 | desconocido |

Ninguna fila pasa a 1. Un README, o el test que vino con el cambio, no
se toma como verificación de nivel 1 aunque esta pasada lo haya
ejecutado o aunque el job de CI lo haya dejado en verde. Donde hay
evidencia ejecutada de que el cambio está en el árbol y sus tests
pasaron, el número nuevo es 2, o 3 si el mismo cambio deja una parte
sin cubrir. Donde no hay esa evidencia, la fila se queda sin nivel.

Un run de Actions con conclusión `failure` no se lee como fallo de
tests si el job `Rust tests, lint, and format` salió `success` y lo que
falló el run fue un job `cancelled` (build o smoke de macOS, al llegar
el push siguiente). Abajo se cita el job, no solo la conclusión del run.

## PRs mergeados en las 24 h anteriores a esta base

Estado `MERGED` y merge commit según `gh pr view`. Cada SHA es ancestro
de `230f4d55` (`git merge-base --is-ancestor`, salida 0).

| PR | Merge commit | Merge (UTC) | Run en `main` | Run | Job rust |
|---|---|---|---|---|---|
| [#209](https://github.com/Mavericksantander/praetore/pull/209) B-NUM | `b2c31e6f2944b300dc7d9b71de541f417d6eae04` | 2026-11-18T04:16:01Z | [44236133647](https://github.com/Mavericksantander/praetore/actions/runs/44236133647) | success | success |
| [#214](https://github.com/Mavericksantander/praetore/pull/214) B-POISON | `e8a6e98b78b74bcc5fe406203977e1d0265201c9` | 2026-11-18T05:11:37Z | [44242509376](https://github.com/Mavericksantander/praetore/actions/runs/44242509376) | success | success |
| [#211](https://github.com/Mavericksantander/praetore/pull/211) ventana firmada | `64eaff67d63364126b49f8d581c4296d0a6aa3bf` | 2026-11-18T05:13:46Z | [44242769184](https://github.com/Mavericksantander/praetore/actions/runs/44242769184) | success | success |
| [#213](https://github.com/Mavericksantander/praetore/pull/213) path check al consumir | `a3a3291b8ffdfa412a9301cd300063e3fdeda3b7` | 2026-11-18T06:04:12Z | [44248626800](https://github.com/Mavericksantander/praetore/actions/runs/44248626800) | success | success |
| [#215](https://github.com/Mavericksantander/praetore/pull/215) B-KEYS | `f2bf8d98e0985b0e5f5b8614ca47f142d6e942ac` | 2026-11-18T06:24:44Z | [44251134936](https://github.com/Mavericksantander/praetore/actions/runs/44251134936) | success | success |
| [#216](https://github.com/Mavericksantander/praetore/pull/216) B-PREFIX | `c6393baf187aeea6e4323d101bbb0ecea6d916a4` | 2026-11-18T06:53:29Z | [44254691868](https://github.com/Mavericksantander/praetore/actions/runs/44254691868) | success | success |
| [#217](https://github.com/Mavericksantander/praetore/pull/217) B-ANCHOR | `00a574f221d11a20f16a874caaf0d689f7c71b43` | 2026-11-18T08:05:50Z | [44264071878](https://github.com/Mavericksantander/praetore/actions/runs/44264071878) | success | success |
| [#203](https://github.com/Mavericksantander/praetore/pull/203) | `8d180b9e62eef62382c1e08de798544fac0fac89` | 2026-11-18T16:47:20Z | [44351273372](https://github.com/Mavericksantander/praetore/actions/runs/44351273372) | failure | success. Cancelados: los dos build macOS de praetore-mcp |
| [#193](https://github.com/Mavericksantander/praetore/pull/193) | `16eee835c3cd92bcb1b09c9174832c2553094a18` | 2026-11-18T16:47:37Z | [44351325303](https://github.com/Mavericksantander/praetore/actions/runs/44351325303) | success | success |
| [#162](https://github.com/Mavericksantander/praetore/pull/162) | `030667018e32c18a9519ac1122019f89067972df` | 2026-11-18T16:47:53Z | [44351375994](https://github.com/Mavericksantander/praetore/actions/runs/44351375994) | failure | success. Job PostgreSQL success. Cancelado: smoke x86_64-apple-darwin |
| [#195](https://github.com/Mavericksantander/praetore/pull/195) | `63ad04f0c4c9b56d3418e9b43c01772d272788c5` | 2026-11-18T16:58:03Z | [44353295569](https://github.com/Mavericksantander/praetore/actions/runs/44353295569) | success | success |
| [#196](https://github.com/Mavericksantander/praetore/pull/196) | `5d71f41980c222ca81c6acef46963fac39154d95` | 2026-11-18T17:48:28Z | [44362750740](https://github.com/Mavericksantander/praetore/actions/runs/44362750740) | failure | success |
| [#145](https://github.com/Mavericksantander/praetore/pull/145) | `66db767049312b69ed0fe7afa5480b01ecc6cc22` | 2026-11-18T17:49:14Z | [44362887764](https://github.com/Mavericksantander/praetore/actions/runs/44362887764) | failure | success. Cancelado: macOS workspace link |
| [#204](https://github.com/Mavericksantander/praetore/pull/204) | `88a24696b4c0f9d6cfaec7ad749f3fbf14271156` | 2026-11-18T17:50:04Z | [44363035476](https://github.com/Mavericksantander/praetore/actions/runs/44363035476) | failure | success. Cancelado: macOS workspace link |
| [#205](https://github.com/Mavericksantander/praetore/pull/205) | `b9e4568352778d4ad10c4973bb529af53aed8146` | 2026-11-18T18:52:57Z | [44374506090](https://github.com/Mavericksantander/praetore/actions/runs/44374506090) | success | success |
| [#206](https://github.com/Mavericksantander/praetore/pull/206) | `559915c0f7fad520f7566f1adea66344608aed23` | 2026-11-18T19:16:42Z | [44378801966](https://github.com/Mavericksantander/praetore/actions/runs/44378801966) | failure | success. Cancelado: macOS workspace link. Smoke de la matriz, skipped |
| [#163](https://github.com/Mavericksantander/praetore/pull/163) migración 0025 | `0b0138692358415721d732f09966937ae15572a3` | 2026-11-18T20:24:30Z | [44390713960](https://github.com/Mavericksantander/praetore/actions/runs/44390713960) | success | success. Job PostgreSQL success |
| [#158](https://github.com/Mavericksantander/praetore/pull/158) delegación | `230f4d55ad5cc2789a6beb7db53fbc7f31cd1ec1` | 2026-11-19T00:10:24Z | [44426846682](https://github.com/Mavericksantander/praetore/actions/runs/44426846682) | in_progress al cerrar esta nota | success. Job PostgreSQL todavía `in_progress` |

El run de `#158` se volvió a consultar con `gh run view 44426846682`
después de los tests locales. Seguía `in_progress`, con el job rust ya
en `success` y PostgreSQL sin conclusión.

## Niveles

Toolchain local: `rustc 1.88.0 (6b00bc388 2025-06-23)` (`cargo +1.88.0`).
El `rustc` por defecto de la máquina era 1.83.0 y no compila este
workspace (`edition = "2024"`, `rust-version = "1.88"`).

La primera corrida de `tests/evasion_paths.rs`, sin el ejemplo
`fake_server`, salió **101**: 0 passed, 5 failed, 1 ignored, pánico
`target/debug/examples/fake_server missing`. No es un fallo del
producto. `cargo +1.88.0 build --locked -p praetore-mcp --bin praetore-mcp --example fake_server`
salió **0**. La corrida de abajo es la que vale.

Comando, exit **0**:

`cargo +1.88.0 test --locked --no-fail-fast -p praetore-mcp --test numeric_gate --test journal_verified_line --test keys_symlinks --test verify_anchor --test journal_exact_chain --test evasion_paths`

| Binario | Resultado |
|---|---|
| `numeric_gate` | ok. 2 passed |
| `journal_verified_line` | ok. 4 passed |
| `keys_symlinks` | ok. 5 passed |
| `verify_anchor` | ok. 6 passed |
| `journal_exact_chain` | ok. 8 passed |
| `evasion_paths` | ok. 5 passed; 1 ignored (`a_symlink_planted_after_the_check_does_not_escape`) |

Otros comandos de esta pasada:

| Comando | Exit | Resultado |
|---|---|---|
| `cargo +1.88.0 test --locked -p praetore-mcp --test evasion a_server_started_without_wrap_runs_the_call_and_leaves_no_receipt -- --exact` | 0 | 1 passed |
| `cargo +1.88.0 test --locked -p praetore-mcp --lib approvals::tests::` | 0 | 10 passed |
| `cargo +1.88.0 test --locked -p praetore-mcp --lib --` y los cinco nombres `a_table_header_is_an_error_and_not_a_warning`, `dotted_argument_field_is_only_a_dot_inside_the_field`, `oversized_line_uses_32600_when_the_id_is_in_the_prefix`, `oversized_line_uses_32700_when_the_id_is_not_extractable`, `observe_ambiguous_line_warning_includes_sha256` | 0 | 5 passed |
| `cargo +1.88.0 test --locked -p praetore-core --test approval_delegation` | 0 | 6 passed |
| `bash scripts/test-check-rust-version.sh` | 0 | `check-rust-version: all cases pass` |
| `bash scripts/check-rust-version.sh` | 0 | `rust-version 1.88 on every package Cargo.toml` |

No se corrió `cargo test --workspace`. No se corrió la batería de
PostgreSQL (no hay `PRAETORE_TEST_DATABASE_URL` en esta máquina). No se
corrió `a_symlink_planted_after_the_check_does_not_escape` con
`--ignored`.

| Capacidad | Antes | Ahora | Evidencia | Qué no autoriza el número |
|---|---|---|---|---|
| B-NUM. El gate decide con el número que lee el servidor (#209) | sin nivel | 2 | Run [44236133647](https://github.com/Mavericksantander/praetore/actions/runs/44236133647), job rust success. Local: `numeric_gate` 2 passed, exit 0 del comando conjunto | No es 1. Son los tests del propio cambio (`tests/numeric_gate.rs`), no una campaña aparte |
| B-POISON. El writer solo agrega una línea que pudo releer (#214) | sin nivel | 2 | Run [44242509376](https://github.com/Mavericksantander/praetore/actions/runs/44242509376), job rust success. Local: `journal_verified_line` 4 passed, mismo exit 0 | No es 1. El literal `99.9999999999999929` lo rechaza #209 como ambiguo antes del writer; el test lo dice. `appended_receipts_always_verify` es el que ejercita el writer |
| Ventana firmada y `HoldInstant` (#211) | sin nivel | 2 | Run [44242769184](https://github.com/Mavericksantander/praetore/actions/runs/44242769184), job rust success. Local: `approvals::tests` 10 passed, exit 0, incluidos `decide_refuses_a_pending_file_edited_to_2099`, `verify_rejects_a_signed_window_longer_than_a_day`, `verify_rejects_a_created_at_in_2099`, `verify_rejects_a_different_fraction_in_the_receipt_second` | No es 1. `spec_defines_decision_window_within_signed_hold_plus_ttl` solo comprueba que el texto de `docs/formal/ApprovalWindow.tla` contiene el nombre del invariante |
| Path check al consumir una aprobación (#213) | sin nivel | 2 | Run [44248626800](https://github.com/Mavericksantander/praetore/actions/runs/44248626800), job rust success. Local: en los mismos 10 passed, `an_unchanged_path_still_consumes_the_approval` y `a_symlink_in_place_of_the_held_directory_does_not_consume_the_approval` | No es 1. Misma salvedad sobre `docs/formal/ApprovalPath.tla`: el test del spec mira el texto |
| B-KEYS. Rechazo estático de symlink, hard link y directorio padre ya presente (#215) | sin nivel | 2 | Run [44251134936](https://github.com/Mavericksantander/praetore/actions/runs/44251134936), job rust success. Local: `keys_symlinks` 5 passed, entre ellos `a_parent_directory_as_a_symlink_is_refused` | No es 1. La carrera del directorio padre queda fuera de este 2. Ver residuales |
| B-PREFIX. `verify` falla si hay una línea fuera de la cadena (#216) | sin nivel | 2 | Run [44254691868](https://github.com/Mavericksantander/praetore/actions/runs/44254691868), job rust success. Local: `journal_exact_chain` 8 passed | No es 1 |
| B-ANCHOR. `verify` sale 0 solo con los dos heads; sin ellos, 3 (#217) | sin nivel | 2 | Run [44264071878](https://github.com/Mavericksantander/praetore/actions/runs/44264071878), job rust success. Local: `verify_anchor` 6 passed | No es 1. Un journal reescrito con las llaves del home sigue pasando si nadie guardó los heads fuera de la máquina: es el contrato, y el test `without_an_anchor_no_journal_is_ok` lo fija en exit 3 |
| Gate de CI: `rust-version` 1.88 uniforme (#203) | sin nivel | 2 | Run [44351273372](https://github.com/Mavericksantander/praetore/actions/runs/44351273372), job rust success (el run quedó failure por builds macOS cancelados). Local: los dos scripts de arriba, exit 0 | No es 1. Es un chequeo de los `Cargo.toml`, no una propiedad de ejecución |
| Contigüidad de `journal_positions` bajo escritores concurrentes (#162) | sin nivel | 2 | Run [44351375994](https://github.com/Mavericksantander/praetore/actions/runs/44351375994): job rust success y job PostgreSQL success. El run quedó failure por el smoke darwin cancelado | No es 1. Esta pasada no reejecutó los tests (no hay Postgres). El PR añade tests; no se leyó el log del job para aislar un nombre |
| Aviso observe de línea ambigua con SHA-256 y largo (#145) | sin nivel | 2 | Run [44362887764](https://github.com/Mavericksantander/praetore/actions/runs/44362887764), job rust success. Local: `observe_ambiguous_line_warning_includes_sha256` ok, exit 0 del comando de los cinco | No es 1. Es un test de unidad del aviso |
| `config.toml` rechaza cabeceras `[tabla]` (#204) | sin nivel | 2 | Run [44363035476](https://github.com/Mavericksantander/praetore/actions/runs/44363035476), job rust success. Local: `a_table_header_is_an_error_and_not_a_warning` ok | No es 1 |
| Condición `arguments.a.b` rechazada (#205) | sin nivel | 2 | Run [44374506090](https://github.com/Mavericksantander/praetore/actions/runs/44374506090), job rust success. Local: `dotted_argument_field_is_only_a_dot_inside_the_field` ok | No es 1. El test local es el del helper, no un `wrap` de punta a punta. El job rust sí corrió `cargo test --workspace --locked` |
| Línea de cliente de más de 32 MiB responde JSON-RPC (#206) | sin nivel | 2 | Run [44378801966](https://github.com/Mavericksantander/praetore/actions/runs/44378801966), job rust success. Local: los dos `oversized_line_uses_32600` / `32700` ok | No es 1 |
| Migración 0025: `ON CONFLICT` no consume posición (#163) | sin nivel | 2 | Run [44390713960](https://github.com/Mavericksantander/praetore/actions/runs/44390713960), conclusión success, job rust success y job PostgreSQL success. `scripts/postgres-ignored-tests.sh` corre cada test `#[ignore]` de `praetore-replay-postgres --test postgres` que no tenga un paso propio, y el test `postgres_journal_position_on_conflict_does_not_consume_a_position` está `#[ignore]` | No es 1. Esta pasada no lo reejecutó. Los huecos de `chain_seq` que ya existían no se reparan: el changelog de `0b01386` lo dice, y no hay test de esta pasada que los cierre |
| Delegación para aprobar (#158) | sin nivel | 3 | Run [44426846682](https://github.com/Mavericksantander/praetore/actions/runs/44426846682), job rust success (el run seguía in_progress). Local: `approval_delegation` 6 passed, exit 0. Esos seis tests cargan el documento; no son el gateway | No es 2 ni 1. La consola firma `schema_version: 1` y `delegation_chain: None` (`crates/praetore-console/src/aprobador.rs`, `ApproverSigner::sign`). El test de Postgres `postgres_delegated_approval_is_recorded_dispatched_exported_and_verified` no tiene resultado en esta nota: el job PostgreSQL del run seguía `in_progress` |
| 6a B-WRAP. El servidor arrancado sin `wrap` corre la llamada y no deja recibo | sin nivel | 5 | Local: `a_server_started_without_wrap_runs_the_call_and_leaves_no_receipt` ok, exit 0. El test pasa porque el hueco sigue. La fila `a` de `docs/security/evasion-matrix.md` lo marca limitación conocida | No se cierra. 5 no es un avance hacia 1 |
| Evasión de rutas de #195, salvo el TOCTOU ignorado | sin nivel | 2 | Run [44353295569](https://github.com/Mavericksantander/praetore/actions/runs/44353295569), job rust success. Local: `evasion_paths` 5 passed, exit 0 del comando conjunto | No es 1. El archivo dice que un test que pasa documenta una defensa que ya estaba. El sexto sigue ignorado |

## Residuales

No se suben.

**TOCTOU de symlink, después de #195.**
`a_symlink_planted_after_the_check_does_not_escape` en
`crates/praetore-mcp/tests/evasion_paths.rs` sigue con
`#[ignore = "hallazgo: PathPrefix ALLOW de un nombre aun inexistente queda same y el tools/call se reenvia; el servidor puede crear ahi un symlink y escribir fuera del root"]`.
En la corrida local salió `ignored` (5 passed, 1 ignored). No se lanzó
con `--ignored`, así que esta pasada no volvió a ver la escritura fuera
del root. Queda sin nivel. No es un 2.

**6a B-WRAP.** Sigue abierto. Nivel 5, con el test de arriba. No hay
cambio que lo cierre en estos merges.

**B-KEYS, symlink en un directorio padre.** El rechazo de un padre que
ya es symlink al momento del `lstat` está dentro del 2
(`a_parent_directory_as_a_symlink_is_refused` pasó). La carrera no. El
cuerpo de
[#215](https://github.com/Mavericksantander/praetore/pull/215) dice, en
"Not verified", que un swap de `DIR/keys` o de un directorio padre entre
el chequeo y el `open` no está verificado: el archivo se abre con
`O_NOFOLLOW`, los directorios no se abren por descriptor
(`crates/praetore-mcp/src/keypath.rs`, `check_keys_dir` recorre
`ancestors` con `symlink_metadata`). Esta pasada no ejecutó esa carrera.
Queda sin nivel. No entra en el 2 de B-KEYS.

## Sin número nuevo

| Qué | Por qué se queda |
|---|---|
| [#193](https://github.com/Mavericksantander/praetore/pull/193), auditoría Ed25519 | Es documentación (`docs/audits/2026-11-16-agilidad-criptografica.md`). El job rust del run [44351325303](https://github.com/Mavericksantander/praetore/actions/runs/44351325303) salió success y no clasifica los sitios de esa auditoría. Sin nivel |
| [#196](https://github.com/Mavericksantander/praetore/pull/196), fixtures de `verify_view` | El job rust del run [44362750740](https://github.com/Mavericksantander/praetore/actions/runs/44362750740) salió success. Esta pasada no reejecutó esos tests. No se le asigna un nivel distinto del 2 de B-ANCHOR, que es el comportamiento que los fixtures miran |
| Huecos de `chain_seq` ya escritos antes de 0025 | El changelog del merge `0b01386` dice que no se reparan. No se sube esa parte |
| Carrera B-KEYS del directorio padre | Sin nivel, arriba |
| TOCTOU `a_symlink_planted_after_the_check_does_not_escape` | Sin nivel, arriba |
| Cualquier fila de esta tabla, hacia 1 | No hay evidencia distinta de los tests del propio cambio y del job rust o PostgreSQL que los corre |

## Qué no se corrió de CI

No hay un job de links de Markdown. El job rust corre `git diff --check`
sobre el árbol y `make demo` (el demo de `docs/DEMO.md`, no este
archivo). `git diff --check` sobre este árbol, en esta pasada, salió **0**.
`make demo` no se corrió: no lee este archivo.
