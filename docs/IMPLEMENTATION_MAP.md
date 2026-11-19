# Mapa de implementación

Observación del 2026-11-19, actualizada sobre la base de abajo, después
de `git fetch origin main`:

| Campo | Valor |
|---|---|
| `git rev-parse origin/main` | `5f5667c3bad76b758fae3aa7d315e8882072b37e` |
| `git log -1` | `Merge pull request #220 from Mavericksantander/cursor/json5-safety-key-detector-36a2` |
| Fecha del merge | 2026-11-19 15:50:32 -0300 |
| `workspace.package.version` | `0.3.6` (`Cargo.toml`) |

`git merge-base --is-ancestor` de ese SHA contra `origin/main` salió 0.
El mismo SHA es el merge que devolvió `gh pr view 220`.

Este archivo no está en `5f5667c3`. En esta pasada
`git cat-file -e 5f5667c3bad76b758fae3aa7d315e8882072b37e:docs/IMPLEMENTATION_MAP.md`
salió 128:

`fatal: path 'docs/IMPLEMENTATION_MAP.md' exists on disk, but not in '5f5667c3bad76b758fae3aa7d315e8882072b37e'`.

`git log --oneline 5f5667c3bad76b758fae3aa7d315e8882072b37e -- docs/IMPLEMENTATION_MAP.md`
no imprimió commits (exit 0). La columna «antes» es **sin nivel** porque
ese commit no tiene un número escrito para estas filas. Los de «ahora»
salen de los comandos y de los runs citados abajo.

Este PR empezó como foto de `230f4d55`. Esta actualización mueve la base
a `5f5667c3`, añade los ocho merges posteriores y corrige la fila de
#158 con la conclusión final del run.

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

## PRs mergeados en las 24 h anteriores a `230f4d55`

Estado `MERGED` y merge commit según `gh pr view`. Cada SHA es ancestro
de `230f4d55` y de `5f5667c3` (`git merge-base --is-ancestor`, salida 0).

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
| [#158](https://github.com/Mavericksantander/praetore/pull/158) delegación | `230f4d55ad5cc2789a6beb7db53fbc7f31cd1ec1` | 2026-11-19T00:10:24Z | [44426846682](https://github.com/Mavericksantander/praetore/actions/runs/44426846682) | success | success. Job PostgreSQL success |

El run de `#158` se volvió a consultar con `gh run view 44426846682`
en esta pasada. Ya terminó: conclusión `success`, job rust `success` y
job PostgreSQL `success`. El nivel de esa fila sigue siendo 3, por la
consola (abajo).

## PRs mergeados después de `230f4d55`, ya en `5f5667c3`

Estado `MERGED` y merge commit según `gh pr view`. Cada SHA es ancestro
de `5f5667c3` (`git merge-base --is-ancestor`, salida 0).

| PR | Merge commit | Merge (UTC) | Run en `main` | Run | Job rust |
|---|---|---|---|---|---|
| [#222](https://github.com/Mavericksantander/praetore/pull/222) B-WRAP install | `2e4b22681f8761d8e1e4048b03469c33ecc6d760` | 2026-11-19T03:34:41Z | [44452412197](https://github.com/Mavericksantander/praetore/actions/runs/44452412197) | success | success |
| [#218](https://github.com/Mavericksantander/praetore/pull/218) ADR-007 | `ff35431693ae0860006b17f59b5317943cc80632` | 2026-11-19T03:35:27Z | [44452506061](https://github.com/Mavericksantander/praetore/actions/runs/44452506061) | success | success |
| [#225](https://github.com/Mavericksantander/praetore/pull/225) `policy coverage` Prefix | `b587249c3fe3c9d1294ae91c911a3874def48d85` | 2026-11-19T04:21:30Z | [44457768592](https://github.com/Mavericksantander/praetore/actions/runs/44457768592) | success | success |
| [#201](https://github.com/Mavericksantander/praetore/pull/201) `install --client claude-code` | `6fec26a23d6ef58838f09bac20033d4b76ddb97e` | 2026-11-19T04:21:55Z | [44457815646](https://github.com/Mavericksantander/praetore/actions/runs/44457815646) | success | success |
| [#224](https://github.com/Mavericksantander/praetore/pull/224) renovación del lock | `c12cfececeb76aeafcf50fda860d3fc28b5f9413` | 2026-11-19T06:35:49Z | [44473325464](https://github.com/Mavericksantander/praetore/actions/runs/44473325464) | success | success. Job PostgreSQL success |
| [#223](https://github.com/Mavericksantander/praetore/pull/223) inventario HighAssurance | `907ca1a213061ab7eb35ba0dee1d183ad6da2205` | 2026-11-19T06:36:10Z | [44473367077](https://github.com/Mavericksantander/praetore/actions/runs/44473367077) | success | success |
| [#219](https://github.com/Mavericksantander/praetore/pull/219) 410 `approved_claim_expired` | `bc83957b778885173033f16e0f10c293b73f045f` | 2026-11-19T18:14:44Z | [44585742867](https://github.com/Mavericksantander/praetore/actions/runs/44585742867) | failure | success. Job PostgreSQL success. Cancelados: los dos build macOS de praetore-mcp |
| [#220](https://github.com/Mavericksantander/praetore/pull/220) detector JSON5 `safety*` | `5f5667c3bad76b758fae3aa7d315e8882072b37e` | 2026-11-19T18:50:33Z | [44592054410](https://github.com/Mavericksantander/praetore/actions/runs/44592054410) | in_progress al cerrar esta nota | Job rust todavía `in_progress`. Job PostgreSQL todavía `in_progress` |

El run de `#220` se consultó con `gh run view 44592054410` al cerrar esta
nota. Todavía no tenía conclusión. El nivel de esa fila, abajo, no se
apoya en ese run.

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

En la pasada original sobre `230f4d55` no se corrió
`cargo test --workspace`. No se corrió la batería de PostgreSQL (no hay
`PRAETORE_TEST_DATABASE_URL` en esta máquina). No se corrió
`a_symlink_planted_after_the_check_does_not_escape` con `--ignored`.

### Pasada de esta actualización (base `5f5667c3`)

Toolchain local: `rustc 1.100.0 (0ef1bc386 2026-11-09)`.
`CARGO_TARGET_DIR` apuntó a un `target/` dentro del worktree.
Antes de los tests se corrió `cargo clean -p praetore-mcp`.

| Comando | Exit | Resultado |
|---|---|---|
| `cargo fmt --all -- --check` | 0 | |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 0 | |
| `cargo clean -p praetore-mcp && cargo test --workspace --locked` | 0 | 1502 passed, 0 failed, 189 ignored |
| `bash scripts/test-check-hook-high-assurance.sh` | 0 | `high assurance inventory check: grep-shaped miss rejected, exact list accepted` |
| `bash scripts/check-hook-high-assurance-tests.sh` | 0 | `all 17 named HighAssurance hook tests ran and passed` |
| `git diff --check` | 0 | |

En esa corrida del workspace salieron ok, entre otros:
`six_a_entries_exit_1_in_dry_run_and_yes`,
`claude_code_six_a_entries_exit_1_in_dry_run_and_yes`,
`claude_code_user_scope_install_uninstall_is_byte_identical`,
`claude_code_local_scope_servers_are_listed_and_end_with_a_warning`,
`policy::tests::coverage_matches_engine_on_tool_prefix`,
`policy::review_pr225::coverage_agrees_with_engine_on_tool_prefix_grid`,
`apd::http_410_code_is_the_signed_approved_claim_expired_reason`,
`apd::journal_claim_expiry_closes_as_approved_claim_expired`,
`proxy::tests::json5_safety_keys_are_refused_in_both_modes` y
`a_server_started_without_wrap_runs_the_call_and_leaves_no_receipt`.

`postgres_safety_tenant_lock_renewal_releases_its_xid_and_can_lose_the_lock`
salió `ignored, requires PRAETORE_TEST_DATABASE_URL`.
`a_symlink_planted_after_the_check_does_not_escape` siguió `ignored`.
No se ejecutó `approve` ni `reject`.

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
| Delegación para aprobar (#158) | sin nivel | 3 | Run [44426846682](https://github.com/Mavericksantander/praetore/actions/runs/44426846682), conclusión success, job rust success y job PostgreSQL success. Local (pasada original): `approval_delegation` 6 passed, exit 0. Esos seis tests cargan el documento; no son el gateway | No es 2 ni 1. La consola, en `5f5667c3`, sigue firmando `schema_version: 1` y `delegation_chain: None` (`crates/praetore-console/src/aprobador.rs:146,151`, `ApproverSigner::sign`). Esta pasada no reejecutó `postgres_delegated_approval_is_recorded_dispatched_exported_and_verified` (sigue `#[ignore]` sin URL) |
| 6a B-WRAP. El servidor arrancado sin `wrap` corre la llamada y no deja recibo | sin nivel | 5 | Local, también en esta pasada: `a_server_started_without_wrap_runs_the_call_and_leaves_no_receipt` ok, exit 0. El test pasa porque el hueco sigue. La fila `a` de `docs/security/evasion-matrix.md:17` en `5f5667c3` sigue diciendo `limitación conocida` | No se cierra. #222 no toca este camino: es el cliente que arranca el servidor a pelo, no el clasificador de `install`. 5 no es un avance hacia 1 |
| Evasión de rutas de #195, salvo el TOCTOU ignorado | sin nivel | 2 | Run [44353295569](https://github.com/Mavericksantander/praetore/actions/runs/44353295569), job rust success. Local: `evasion_paths` 5 passed, exit 0 del comando conjunto | No es 1. El archivo dice que un test que pasa documenta una defensa que ya estaba. El sexto sigue ignorado |
| Install: un wrap de otro binario, home o modo no es «already wrapped» (#222) | sin nivel | 2 | Run [44452412197](https://github.com/Mavericksantander/praetore/actions/runs/44452412197), conclusión success, job rust success. En `5f5667c3`, `is_wrapped` exige `command == target.exe` y `--dir` / `--mode` una sola vez e iguales (`crates/praetore-mcp/src/install.rs:255-265`); el rechazo usa `NOT_GOVERNED` (`install.rs:25`). Esta pasada: `six_a_entries_exit_1_in_dry_run_and_yes` y `claude_code_six_a_entries_exit_1_in_dry_run_and_yes` ok (`crates/praetore-mcp/tests/install.rs:669,737`) | No es 1. Son tests del propio cambio. No cierra la fila 6a de arriba. `is_wrapped` no lee `env`; eso queda fuera de este 2 (residuales) |
| `policy coverage` trata un `tool` Prefix como selector (#225) | sin nivel | 2 | Run [44457768592](https://github.com/Mavericksantander/praetore/actions/runs/44457768592), conclusión success, job rust success. Esta pasada: `policy::tests::coverage_matches_engine_on_tool_prefix` y `policy::review_pr225::coverage_agrees_with_engine_on_tool_prefix_grid` ok (`crates/praetore-mcp/src/policy.rs:1213,1283`) | No es 1. Son tests del propio cambio |
| `install --client claude-code` (#201) | sin nivel | 3 | Run [44457815646](https://github.com/Mavericksantander/praetore/actions/runs/44457815646), conclusión success, job rust success. Esta pasada: `claude_code_user_scope_install_uninstall_is_byte_identical` ok y `claude_code_local_scope_servers_are_listed_and_end_with_a_warning` ok (`crates/praetore-mcp/tests/install.rs:276,336`). El segundo fija el aviso `This version does not wrap local scope` (`tests/install.rs:362`) | No es 2 ni 1. El scope `local` no se envuelve |
| Gate de CI: inventario HighAssurance desde `cargo test --list` (#223) | sin nivel | 2 | Run [44473367077](https://github.com/Mavericksantander/praetore/actions/runs/44473367077), conclusión success, job rust success. Esta pasada: `scripts/test-check-hook-high-assurance.sh` exit 0 (rechaza un listado que solo parece una corrida) y `scripts/check-hook-high-assurance-tests.sh` exit 0, `all 17 named HighAssurance hook tests ran and passed` | No es 1. Es un chequeo de inventario y de que esos tests corren, no una propiedad nueva del hook |
| HTTP 410 de un dispatch tardío usa la razón firmada `approved_claim_expired` (#219) | sin nivel | 2 | Run [44585742867](https://github.com/Mavericksantander/praetore/actions/runs/44585742867): job rust success y job PostgreSQL success (el run quedó failure por los dos builds macOS cancelados). En `5f5667c3`: `GatewayError::ApprovedClaimExpired` (`crates/praetore-gateway/src/lib.rs:617`) y el 410 con `code` `approved_claim_expired` (`crates/praetore-gateway/src/http_api.rs:1046-1048`). Esta pasada: `apd::http_410_code_is_the_signed_approved_claim_expired_reason` y `apd::journal_claim_expiry_closes_as_approved_claim_expired` ok (`crates/praetore-gateway/tests/enforcement.rs:3798,3766`) | No es 1. Son tests del propio cambio. El CHANGELOG lo marca como cambio visible de contrato |
| Detector `safety*`: lee formas JSON5 (#220) | sin nivel | 2 | En `5f5667c3`: `json5_texts` (`crates/praetore-mcp/src/proxy.rs:594`) y `proxy::tests::json5_safety_keys_are_refused_in_both_modes` (`proxy.rs:1575`), ok en esta pasada. El run [44592054410](https://github.com/Mavericksantander/praetore/actions/runs/44592054410) de `main` seguía sin conclusión al cerrar esta nota (job rust `in_progress`) | No es 1. El nivel se sostiene por el test local y porque ese test está en el árbol de `5f5667c3`, no por el run. Es el test del propio cambio |

## Residuales

No se suben.

**TOCTOU de symlink, después de #195.**
`a_symlink_planted_after_the_check_does_not_escape` en
`crates/praetore-mcp/tests/evasion_paths.rs` sigue con
`#[ignore = "hallazgo: PathPrefix ALLOW de un nombre aun inexistente queda same y el tools/call se reenvia; el servidor puede crear ahi un symlink y escribir fuera del root"]`.
En la corrida local salió `ignored` (5 passed, 1 ignored). No se lanzó
con `--ignored`, así que esta pasada no volvió a ver la escritura fuera
del root. Queda sin nivel. No es un 2.

**6a B-WRAP, servidor sin `wrap`.** Sigue abierto. Nivel 5, con el test
de arriba, que en esta pasada volvió a salir ok. La fila `a` de
`docs/security/evasion-matrix.md:17` en `5f5667c3` sigue como
`limitación conocida`. #222 no cierra este hueco: cambia el clasificador
de `install` (una entrada que parsea como `wrap` de otro binario, home o
modo ya no se reporta «already wrapped»), no el caso de un servidor
arrancado a pelo.

**#222, `env` de la entrada.** `is_wrapped` solo compara `command`,
`--dir` y `--mode` (`crates/praetore-mcp/src/install.rs:255-265`). No
lee `env`. Esta pasada no inyectó un cargador; el residual queda
confirmado por ese código, sin nivel aparte.

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
| [#218](https://github.com/Mavericksantander/praetore/pull/218), ADR-007 | Solo documentación: `docs/adr/007-unify-mcp-and-gateway.md` y la entrada en `docs/adr/README.md`. El job rust del run [44452506061](https://github.com/Mavericksantander/praetore/actions/runs/44452506061) salió success. No cambia código de runtime. Sin nivel |
| [#224](https://github.com/Mavericksantander/praetore/pull/224), renovación del tenant lock | El comportamiento de producción no cambia: `TenantLock::renew` llama `renew_after` con un hook vacío (`crates/praetore-replay-postgres/src/safety.rs:477-479`). El test `postgres_safety_tenant_lock_renewal_releases_its_xid_and_can_lose_the_lock` (`tests/postgres.rs:9543`) está `#[ignore]` y en esta pasada salió ignored por falta de `PRAETORE_TEST_DATABASE_URL`. El job PostgreSQL del run [44473325464](https://github.com/Mavericksantander/praetore/actions/runs/44473325464) salió success. Sin número de producto nuevo |
| Huecos de `chain_seq` ya escritos antes de 0025 | El changelog del merge `0b01386` dice que no se reparan. No se sube esa parte |
| Carrera B-KEYS del directorio padre | Sin nivel, arriba |
| TOCTOU `a_symlink_planted_after_the_check_does_not_escape` | Sin nivel, arriba |
| Cualquier fila de esta tabla, hacia 1 | No hay evidencia distinta de los tests del propio cambio y del job rust o PostgreSQL que los corre |

## Qué no se corrió de CI

No hay un job de links de Markdown. El job rust corre `git diff --check`
sobre el árbol y `make demo` (el demo de `docs/DEMO.md`, no este
archivo). `git diff --check` sobre este árbol, en esta pasada, salió **0**.
`make demo` no se corrió: no lee este archivo. El run de `#220` en `main`
aún no había terminado al cerrar esta nota.
