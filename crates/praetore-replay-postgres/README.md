# praetore-replay-postgres

Backend PostgreSQL de los stores de replay y journal de praetore.

## Tests de integración

Los tests de `tests/postgres.rs` están marcados `#[ignore]` porque necesitan un
servidor PostgreSQL real. Se apuntan con `PRAETORE_TEST_DATABASE_URL`.

### Corrida normal (19 tests)

```sh
export PRAETORE_TEST_DATABASE_URL=postgres://postgres@localhost:5432/postgres
cargo test -p praetore-replay-postgres -- --include-ignored \
  --skip replay_claim_survives_server_restart \
  --skip postgres_journal_survives_server_restart_without_automatic_dispatch
```

### Tests de reinicio (dos fases)

Estos dos tests verifican que el estado sobrevive a un reinicio real del
servidor. Fallan si se corren en una sola pasada: hay que correr la fase
`before`, reiniciar PostgreSQL y correr la fase `after`.

| Test | Variable de fase |
|---|---|
| `replay_claim_survives_server_restart` | `PRAETORE_TEST_RESTART_PHASE` |
| `postgres_journal_survives_server_restart_without_automatic_dispatch` | `PRAETORE_TEST_JOURNAL_RESTART_PHASE` |

```sh
T=replay_claim_survives_server_restart
PRAETORE_TEST_RESTART_PHASE=before \
  cargo test -p praetore-replay-postgres --test postgres -- --include-ignored --exact $T
pg_ctl -D "$PGDATA" restart -w   # o el reinicio equivalente de tu servicio
PRAETORE_TEST_RESTART_PHASE=after \
  cargo test -p praetore-replay-postgres --test postgres -- --include-ignored --exact $T
```

Para el test del journal, el mismo procedimiento con
`PRAETORE_TEST_JOURNAL_RESTART_PHASE`.
