# SAF-12 · Aprobación humana de REQUIRE_APPROVAL en praetore-mcp (propuesta)

Estado: **propuesta, solo documento.** No contiene código. Base: `origin/main` en `b63252f`. Todas las referencias `archivo:línea` son contra ese commit.
Nombre: sigue la convención `SAF-NN-…`. El número 12 es provisional y lo confirma el CTO. SAF-11 es la propuesta de custodia de llaves (#44).
Contexto: tarea G6 de la etapa 2, según la redefinición del CTO del 30-oct-2026. En el BRIEF original, este trabajo era G8.

## 1. Decisiones

Las decisiones 1 a 5 son las posturas iniciales del CTO del 30-oct-2026. Ninguna está DECIDIDA: falta la aprobación del fundador. Las decisiones 6 a 9 son nuevas y salieron al revisar el código (§2).

| # | Decisión | Estado |
|---|---|---|
| 1 | Mover `ApprovalChallenge`, `HumanApprovalDecision`, `HumanApprovalVerifier` (más `ApprovalError`, `authority_tenant_id` y el dominio `PRAETORE_HUMAN_APPROVAL_V1\0`) a `praetore-core::approval`. `praetore-gateway` los reexporta con el mismo nombre. praetore-mcp no pasa a depender de axum ni de tokio. | PROPUESTA (postura del CTO) |
| 2 | `init` crea la llave del aprobador y sus pins. En un home existente, `praetore-mcp init --add-approver` la agrega y es idempotente. Sin aprobador configurado, REQUIRE_APPROVAL se sigue denegando (fail-closed), igual que hoy. | PROPUESTA (postura del CTO) |
| 3 | `approve` autoriza **una sola vez** la siguiente llamada **idéntica** del cliente. Se compara el `action_digest` canónico de servidor, herramienta y argumentos, con un TTL corto. `approve` nunca relanza la acción por su cuenta, así que el resultado le llega al agente. | PROPUESTA (postura del CTO) |
| 4 | El consumo de una aprobación se guarda en disco, en el home, con `fsync` del archivo y del directorio **antes** de reenviar la llamada. Sobrevive a un reinicio. Un doble uso, incluso concurrente, se deniega. Hay tests de reinicio y de concurrencia. | PROPUESTA (postura del CTO) |
| 5 | `decided_by` se alinea con el dispatch aprobado del gateway. **v4 alcanza, sin cambios** (ver §4): la llamada reenviada lleva su propio recibo v4 con `outcome: RequireApproval` y `decided_by: Rule { rule_id }`, igual que en el gateway, y queda ligada a la aprobación firmada por claves de `context`. Ni el formato ni la precedencia cambian. | PROPUESTA |
| 6 | **Ventana de aprobación.** Hoy duraría unos 60 s (ver §2.3). Propuesta: subir `INTENT_LIFETIME` y el lease de `LocalFreshness` de praetore-mcp a 10 minutos, para todas las llamadas. | PROPUESTA (nueva) |
| 7 | **Autoaprobación por el agente.** Si el agente tiene una terminal (Bash de Claude Code, la terminal de Cursor), podría correr `praetore-mcp approve` por su cuenta. Propuesta: `approve` exige una terminal interactiva y que se escriba un código de confirmación de 6 caracteres mostrado en pantalla. Y queda documentado como límite: **no** es una frontera fuerte con llaves LOCAL/DEV en la misma máquina. | PROPUESTA (nueva) |
| 8 | **`verify` comprueba la cadena completa**: el recibo de la llamada denegada, la decisión firmada, el consumo y el recibo de la llamada reenviada. Un recibo `RequireApproval` reenviado que no tenga una aprobación válida cuenta como FAIL. | PROPUESTA (nueva) |
| 9 | **Hay un comando `reject <id>`**, que firma `outcome: Reject`. La llamada siguiente se deniega como hoy, y en `approvals list` el pedido aparece como rechazado. | PROPUESTA (nueva) |

## 2. Estado actual verificado (solo lectura, `b63252f`)

### 2.1 praetore-mcp
- REQUIRE_APPROVAL en enforce se bloquea con un texto fijo: `crates/praetore-mcp/src/proxy.rs:393`. En observe solo se registra.
- La evidencia se arma en `Gate::evaluate_evidence` (`crates/praetore-mcp/src/gate.rs:221-252`):
  - `Action::new(ACTION_TYPE, Some(server), build_parameters(...))` con la capacidad `mcp:tools/call`. La acción es determinista para la misma terna (servidor, herramienta, argumentos), así que su `action_digest` también lo es.
  - El contexto lleva `praetore.mode` (`gate.rs:24,234`) y el proxy.
  - El intent v2 dura `INTENT_LIFETIME = 60 s` (`gate.rs:32,245`).
- La freshness local da un lease de un minuto (`gate.rs:149`).
- El replay guard está **en memoria** (`gate.rs:123-145`): no expira entradas y falla cerrado al llegar a 1 000 000.
- `init` crea tres llaves: issuer, agent y attester (`crates/praetore-mcp/src/store.rs:76-110`). Sobre un home ya inicializado no hace nada (`store.rs:127,134`).
- praetore-mcp depende solo de `praetore-core` (más hex, serde, sha2, time, uuid y zeroize).

### 2.2 Gateway (referencia que hay que alinear)
- Dominio de firma: `PRAETORE_HUMAN_APPROVAL_V1\0` (`crates/praetore-gateway/src/lib.rs:134`). Tenant: `authority_tenant_id` (`:150`).
- `ApprovalChallenge` (`:166`):
  - campos `tenant_id`, `agent_id`, `request_id`, `evidence_id`, `evidence_hash`, `action_digest`, `policy_digest` y `expires_at`;
  - `from_evidence` (`:179`) calcula `expires_at = min(intent_v2.expires_at, freshness_valid_until)`.
- `HumanApprovalDecision` (`:270`) incluye `approval_id`, `approver_key_id`, el `challenge`, `outcome ∈ {approve, reject}` y la firma Ed25519 sobre dominio ‖ JSON canónico.
- `HumanApprovalVerifier` (`:520`) se puede limitar a un tenant (`for_tenant`).
- `verify_decision_for_record` (`:944-969`):
  - exige que el challenge sea el derivado de la evidencia persistida;
  - exige un solo verificador aplicable;
  - rechaza `SelfApproval` cuando la llave o el id del aprobador son los del agente (`:965-967`).
- **El dispatch aprobado no crea evidencia nueva.** La evidencia sigue con `outcome: RequireApproval` y `decided_by: Rule { rule_id }`.
  - `claim_dispatch` (`:1308-1370`) vuelve a verificar la aprobación guardada y la evidencia, y después reclama el dispatch único en el journal.
  - El resultado se registra como `ExecutionAttestation` (`crates/praetore-receipt/src/lib.rs:133`, `record_terminal_attested` en `lib.rs:1507`).
- Usuarios actuales de estos tipos, que el cambio de la decisión 1 obliga a tocar:
  - `praetore-cli`;
  - `praetore-gateway-service` (`approver_bindings.rs`, `main.rs`);
  - `praetore-gateway` (`http_api.rs`, `tests/enforcement.rs`);
  - `praetore-replay-postgres` (`execution.rs`, `tests/postgres.rs`).

### 2.3 Consecuencia: la ventana sería de 60 s
`ApprovalChallenge::from_evidence` toma el **mínimo** entre el vencimiento del intent y el de la freshness. En praetore-mcp ambos son de 60 s, así que con el código de hoy el humano tendría **como mucho 60 s** desde la llamada denegada para firmar. Eso motiva la decisión 6.
- Subir los dos a 10 minutos solo hace que, en el replay guard, cada id de request sea único durante más tiempo. El guard no expira entradas (§2.1), así que no cambia el uso de memoria.
- Alternativa descartada: que praetore-mcp calcule su propia ventana. Se apartaría de la semántica de `from_evidence`, y entonces el challenge firmado ya no sería el mismo que verifica el gateway.

## 3. Diseño

### 3.1 Archivos nuevos en el home (todos 0600, directorios 0700)
```
keys/approver.local-dev.key        LOCAL/DEV Ed25519 (decisión 2)
approver-pins.jsonl                key_id + clave pública, formato de issuer-pins
approvals/pending/<evidence_id>.json   ApprovalChallengeView {challenge, action} — escrito al bloquear
approvals/decided/<evidence_id>.json   HumanApprovalDecision firmada — escrito por approve/reject (O_EXCL)
approvals/consumed/<approval_id>       marcador de un solo uso — O_EXCL + fsync archivo + fsync dir (decisión 4)
```
Los directorios con symlink se rechazan, igual que hoy pasa con `keys/` y `receipts/`.

### 3.2 Flujo
1. **La llamada queda en espera.** En enforce, el resultado es `RequireApproval`, con la regla `r` y la evidencia E1, que ya se registra hoy.
   - Si hay aprobador configurado, además se escribe `pending/<E1>.json`.
   - El cliente recibe un `isError` con el texto `Requires human approval. Run: praetore-mcp approve <E1> (expires <hora UTC>). Evidence id: <E1>`.
   - Sin aprobador, el texto de hoy no cambia.
2. **`praetore-mcp approvals list`** muestra los pedidos pendientes, decididos y vencidos.
3. **`praetore-mcp approve <E1>`**:
   - lee `pending/<E1>.json` y comprueba que `action_matches_challenge()` se cumpla y que `now < challenge.expires_at`;
   - muestra la acción completa: servidor, herramienta y argumentos, con el texto saneado por `display_safe`;
   - exige una TTY y que se escriba el código (decisión 7);
   - firma `HumanApprovalDecision { outcome: approve }` con la llave del aprobador y la escribe en `decided/<E1>.json` con O_EXCL. Si ya existe una decisión, falla.
   - No contacta al servidor MCP ni relanza nada (decisión 3).
4. **Reintento del cliente.** Para cada `tools/call`, el proxy primero arma la `Action` y calcula su `action_digest` (D). Si hay en `decided/` una aprobación vigente con `challenge.action_digest == D` que no esté en `consumed/`:
   - Se evalúa la llamada **con el contexto adicional** `praetore.approval_id = <approval_id>` y `praetore.approved_evidence_id = <E1>`. El resultado es E2.
   - Si E2 es `RequireApproval` por **la misma regla `r`**, la decisión verifica contra `approver-pins.jsonl` (y no es autoaprobación) y no pasó el TTL de reintento, el proxy:
     - crea `consumed/<approval_id>` con O_EXCL, y hace `fsync` del archivo y del directorio;
     - **solo después** reenvía la llamada.
   - Si E2 es `Deny` (la política cambió), se bloquea, no se consume la aprobación y gana el Deny, como manda la precedencia.
   - Si E2 es `Allow`, se reenvía sin consumir la aprobación.
   - Si el O_EXCL falla porque ya existe el marcador (concurrencia o reuso), la llamada se trata como sin aprobación y se bloquea.
5. **TTL de reintento** (decisión 3): 120 s desde la firma, sin pasar nunca de `challenge.expires_at` + 120 s.

### 3.3 Qué no cambia
- Formato de evidencia v4, precedencia `Recover > Deny > RequireApproval > Allow`, motor de políticas y modo observe. En observe REQUIRE_APPROVAL nunca bloquea, así que no hay nada que aprobar: `approve` sobre una evidencia de observe falla.
- Multi-tenant: el verificador se crea con `for_tenant(authority_tenant_id(...))` y todo el estado vive en el home de una instalación. No hay nada compartido entre tenants ni entre homes.

## 4. `decided_by` y recibos (decisión 5)

| Recibo | Firmado por | `outcome` / `decided_by` | Vínculo |
|---|---|---|---|
| E1, la llamada bloqueada | attester (v4, igual que hoy) | `RequireApproval` / `Rule { r }` | — |
| Decisión | approver (`PRAETORE_HUMAN_APPROVAL_V1\0`) | `approve` o `reject` | `challenge.evidence_id = E1`, `evidence_hash`, `action_digest` |
| E2, la llamada reenviada | attester (v4) | `RequireApproval` / `Rule { r }` | `context["praetore.approval_id"]` y `context["praetore.approved_evidence_id"]`, dentro del payload firmado |

- Es la misma forma que en el gateway, donde un dispatch aprobado también ejecuta una evidencia `RequireApproval` con `Rule { r }`, protegida por una `HumanApprovalDecision`. `context` ya forma parte del payload firmado (hoy lleva `praetore.mode`), así que agregar dos claves **no** cambia el formato.
- **Diferencia con el gateway.** praetore-mcp no emite una `ExecutionAttestation`, porque no ve el resultado de la herramienta como un despacho. El resultado vuelve al cliente sin parsear (`relay.rs`). Si el CTO quiere un recibo del resultado, sería otra propuesta.
- **Cuándo v4 dejaría de alcanzar:** si se pidiera que E2 diga `Allow` con `decided_by` = «aprobación humana». Eso exigiría una variante nueva de `DecidedBy` (`crates/praetore-core/src/decision.rs:56`), es decir, un cambio de formato. **No se propone.**

## 5. Mover los tipos a core (decisión 1)
- Módulo nuevo `praetore-core::approval` con `ApprovalChallenge`, `ApprovalChallengeView`, `HumanApprovalOutcome`, `HumanApprovalDecision`, `HumanApprovalVerifier`, `ApprovalError`, `authority_tenant_id` y la constante del dominio.
- `ApprovalChallengeView::action_matches_challenge` usa `action_digest`, que hoy vive en `praetore-receipt` (`crates/praetore-receipt/src/lib.rs:26`). Hay dos opciones:
  - **(a)** mover `action_digest` a core, y que receipt lo reexporte;
  - **(b)** que praetore-mcp dependa de `praetore-receipt`, que solo trae hex, serde, sha2, thiserror, time y uuid, sin la feature `signing`.

  Propuesta: **(a)**, para que el challenge y su digest vivan en el mismo crate.
- Los bytes firmados no cambian (mismo dominio, mismo JSON canónico). Las aprobaciones ya guardadas en Postgres y los fixtures de `tests/enforcement.rs` tienen que seguir verificando: es un test obligatorio del PR.
- `praetore-gateway` hace `pub use praetore_core::approval::*`, así que los crates que hoy importan estos tipos desde el gateway compilan sin cambios. El PR lo demuestra sin tocar sus `use`.
- Dependencias nuevas: ninguna. `ed25519-dalek` ya es dependencia de core (verificación); praetore-mcp ya firma con sus llaves locales.

## 6. Tests (se escriben antes que el código)
- **Concurrencia:** N hilos (o N procesos `wrap`) reintentan la misma llamada aprobada. Exactamente uno se reenvía y los N−1 reciben `isError`. Con N=2 y N=16.
- **Reinicio:** se aprueba, se consume y se mata el proceso. Un `wrap` nuevo con el mismo home rechaza el reintento. Otro caso: se aprueba, se mata el proceso **antes** del consumo y un `wrap` nuevo permite exactamente un uso.
- **Crash entre el consumo y el reenvío:** el marcador existe y la llamada no se reenvió. La aprobación queda gastada (fail-closed), y `approvals list` muestra `consumed` sin un E2.
- **Identidad:** el reintento con un argumento distinto, con otro servidor o con otra herramienta no consume la aprobación y se bloquea.
- **Vencimiento:** `approve` después de `expires_at` falla; un reintento después del TTL se bloquea.
- **Sin aprobador:** el bloqueo es igual al de hoy y no se escribe `pending/`.
- **Autoaprobación:** si la llave del aprobador es la del agente, `approve` y el proxy la rechazan.
- **Precedencia:** con una regla Deny agregada después de aprobar, gana el Deny y la aprobación no se consume.
- **Sin TTY:** `approve` sin terminal falla.
- **`verify`:** una cadena válida da OK. Un E2 sin aprobación, una decisión de otro challenge o un marcador sin E2 dan FAIL o warning, según la tabla de §4.
- **Compatibilidad:** las decisiones firmadas que ya existen (fixtures del gateway y Postgres) verifican igual después de mover los tipos.
- **Prueba real:** server-filesystem 2.1.0, con REQUIRE_APPROVAL en `write_file`, `approve` y el reintento hecho por el cliente. En Claude Desktop o Cursor, y en un chat (no en una sesión Code; ver GUIDE.md, límite 1).

## 7. Riesgos y límites
- **Las llaves son LOCAL/DEV.** El aprobador, el agente y el attester viven en la misma máquina y bajo el mismo usuario. Quien pueda leer `keys/` puede aprobar. La decisión 7 solo pone fricción: no convierte la aprobación en una frontera. Va a GUIDE.md.
- **TOCTOU:** sigue igual. El servidor ejecuta después de que el proxy decide.
- **Con 10 minutos de ventana (decisión 6),** un intent capturado vale más tiempo. Hoy el proxy es el único que firma y consume intents, y el replay guard sigue en memoria. Hacerlo durable queda fuera de esta propuesta.
- **Un crash entre el consumo y el reenvío gasta la aprobación sin ejecutar.** Es fail-closed: la alternativa (reenviar y después consumir) permitiría un doble uso.

## 8. Fuera de alcance
- Aprobación remota o desde otra máquina, notificaciones, interfaz web, varios aprobadores o quórum.
- Recibo del resultado de la herramienta (§4).
- Que el replay guard de intents sea durable.

## 9. Preguntas abiertas
1. ¿10 minutos para la decisión 6, u otro valor?
2. ¿TTL de reintento de 120 s?
3. ¿(a) o (b) en §5?
4. ¿`reject` entra en este alcance (decisión 9)?
