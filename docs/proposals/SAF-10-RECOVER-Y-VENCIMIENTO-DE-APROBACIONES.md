# SAF-10 · Recover y vencimiento de aprobaciones (propuesta)

Estado: **propuesta, solo documento.** No contiene código de producción. Base: `main` local en `3db7b5e`; `origin/main` está en `a797bea`, 22 commits adelante, y en esa revisión tampoco hay un evento de vencimiento persistido (ver §2).
Nombre: sigue la convención `SAF-NN-…` de `SAF-09-safety-actions-break-glass.md`. El número SAF-10 es provisional y lo confirma el CTO.
Contexto: nota interna de investigación `org/praetore/research/10-semantica-decisiones-recover-approval.md`, del 29-oct-2026 (workspace PRÆTOR, fuera del repo).
Alcance: semántica de decisión y evidencia. Para autonomía física aplica solo al nivel de misión y modo (no al lazo rápido) y solo a la plataforma no armada.

## 1. Decisiones

| # | Decisión | Estado |
|---|---|---|
| 1 | Se mantiene `DecisionOutcome {Allow, RequireApproval, Deny}` y se agrega `recovery: Option<RecoveryObligation>`. No hay un cuarto valor en el enum. | **DECIDIDA** (CTO, 29-oct-2026) |
| 2 | Severidad: Recover > Deny > RequireApproval > Allow. La recuperación que exige el piso sobrevive a un Deny de otra capa: el Deny bloquea la acción, pero no el paso a modo seguro (alternativa A). | **DECIDIDA** (CTO, 29-oct-2026) |
| 3 | Un timeout de aprobación equivale a Deny y deja un recibo `ApprovalExpired` firmado. Nunca se aprueba por silencio. | **DECIDIDA** (CTO, 29-oct-2026) |
| 4 | Validación: RequireApproval queda prohibido en el lazo rápido, o cuando δ es menor que el plazo de aprobación. | **DECIDIDA** (CTO, 29-oct-2026) |
| 5 | Los tests de propiedad se escriben antes de cualquier implementación. | **DECIDIDA** (CTO, 29-oct-2026) |

## 2. Estado actual verificado (solo lectura)

- `crates/praetore-core/src/decision.rs:17-21`: el enum tiene tres valores. `:24-33`: `strongest` aplica Deny > RequireApproval > Allow.
- `crates/praetore-gateway/src/lib.rs`:
  - `:180-185`: `ApprovalResolution {Pending, Approved, Rejected, Expired}`.
  - `:137-147`: el plazo de aprobación es `min(intent.expires_at, freshness_valid_until)`.
  - `:826-850`: `approval_resolution` **calcula** `Expired` al consultar.
  - `:941-951`: mapea `IntentInvalid` y `FreshnessExpired` a `ApprovalError::Expired`.
  - `:288`: define el error `ApprovalError::Expired`.
- `crates/praetore-gateway/src/http_api.rs:197,215,283-284`: HTTP 410 `approval_expired`.
- `crates/praetore-cli/src/main.rs:1358-1381`: el CLI muestra `Expired`.
- Migraciones `0001`–`0008`:
  - `0006_human_approvals.sql` solo admite `outcome IN ('approve','reject')`.
  - `0004_execution_journal_events.sql` registra solo transiciones de `execution_status` (`not_dispatched`, …, `failed`), sin estado de aprobación.
- Tests: `crates/praetore-gateway/tests/enforcement.rs:1127` (`expired_human_rejection_uses_the_engine_clock`). Cubre el rechazo, no la persistencia.
- **Conclusión:** el vencimiento existe como estado calculado y como error HTTP, pero **no como evento ni como recibo firmado persistido**.
  - Revisado en `3db7b5e`, en `origin/main` (`a797bea`) y en las ramas `feat/receipt-decided-by`, `feat/receipt-policy-hash-v2` y `feat/t013-sandbox-dispatcher`.
  - Ninguna tiene migraciones posteriores a `0008`.

## 3. Cambios de tipos (revisado por el CTO, 29-oct-2026: una sola Policy, sin capas)

```text
// praetore-core (sin cambios en el enum)
enum DecisionOutcome { Allow, RequireApproval, Deny }

struct RecoveryObligation {
    recovery_id: String,   // modo seguro predeclarado en la política
    rule_id: String,       // regla Recover que la originó
    reason: String,
    deadline_ms: u64,      // T_recover_max, > 0
}

struct Decision {
    outcome: DecisionOutcome,
    reason: String,
    contributions: Vec<DecisionContribution>,
    recovery: Option<RecoveryObligation>,   // nuevo; omitido si None
}
// Invariante: recovery.is_some()  =>  outcome == Deny (rechazado al deserializar)
// Severidad efectiva: sev(d) = Recover si recovery.is_some(), si no, outcome
//                     Recover > Deny > RequireApproval > Allow

enum PolicyEffect { Allow, Deny, RequireApproval, Recover { recovery_id, deadline_ms } }
// Recover como efecto de regla produce outcome = Deny + recovery = Some(..)

struct Policy { ..., max_approval_ms: Option<u64> }          // nuevo, opcional
struct PolicyRule { ..., control_loop: Option<fast|slow>, delta_ms: Option<u64> }  // nuevos, opcionales
// Los campos nuevos llevan skip_serializing_if = None: el digest de una política
// sin ellos no cambia y no se sube canonical_version ni semantics_version.

// Combinación entre reglas que coinciden dentro de una sola Policy
strongest(a, b):
    outcome  = a.outcome.strongest(b.outcome)
    recovery = a.recovery.or(b.recovery)        // una obligación nunca se descarta
    if recovery.is_some() { outcome = Deny }

// Gateway
enum ApprovalResolution { Pending, Approved, Rejected, Expired }   // sin cambios
struct ApprovalExpiredReceipt {
    schema_version, tenant_id, agent_id, request_id,
    evidence_id, evidence_hash, action_digest, policy_digest,
    expires_at,          // el mismo del desafío
    observed_at,         // reloj del motor (validate_evidence_time_bounds), no del host
    effective_outcome: "deny",
    gateway_key_id, signature,
}
```

- Compatibilidad: `Decision` y `Evidence` usan `deny_unknown_fields`. La evidencia que lleva `recovery` es v3; la evidencia v1 y v2 sin `recovery` sigue verificando.

## 4. Combinación entre reglas de una sola Policy

| regla A \ regla B | Allow | RequireApproval | Deny | Recover |
|---|---|---|---|---|
| Allow | Allow | RequireApproval | Deny | Deny + recovery(B) |
| RequireApproval | RequireApproval | RequireApproval | Deny | Deny + recovery(B) |
| Deny | Deny | Deny | Deny | Deny + recovery(B) |
| Recover | Deny + recovery(A) | Deny + recovery(A) | Deny + recovery(A) | Deny + recovery |

- La admisión sigue `strongest`, de modo que deny gana.
- Una regla Recover conserva su obligación aunque otra regla niegue (decisión 2, alternativa A). Es una divergencia deliberada con XACML 3.0 §7.18.
- **Trabajo futuro:** la composición piso × tenant (dos capas de política) no se implementa en SAF-10.

## 5. Semántica del timeout de aprobación

1. Plazo: `T_approval ≤ min(intent.expires_at, freshness_valid_until)`, igual que hoy.
2. Al vencer: el resultado efectivo es **Deny**. No se despacha, y la decisión humana tardía se rechaza (HTTP 410, igual que hoy).
3. Nunca se aprueba por silencio. Ninguna configuración, ni de piso ni de tenant, puede convertir un vencimiento en Allow.
4. El gateway emite y persiste **una sola vez** un `ApprovalExpiredReceipt` firmado. Se dispara en la primera detección (consulta de estado, intento de resolver o barrido) y es idempotente por `(agent_id, request_id)`.
5. Reloj: se usa el reloj configurado del motor, como ya establece `docs/assurance-matrix.md:23`.

## 6. Migración necesaria (confirmada en §2)

`0009_human_approval_expirations.sql` (nombre provisional):
- Tabla `praetore.human_approval_expirations`:
  - Columnas: `agent_id`, `request_id`, `tenant_id`, `evidence_id`, `evidence_hash`, `action_digest`, `policy_digest`, `expires_at`, `observed_at`, `gateway_key_id`, `receipt_json JSONB`, `signature`.
  - `UNIQUE (agent_id, request_id)` y FK a `execution_journal`.
- Triggers append-only (sin UPDATE, DELETE ni TRUNCATE), con el mismo patrón que `0006`.
- RLS por tenant, con el mismo patrón que `0008`.
- Restricción de exclusión: una misma `(agent_id, request_id)` no puede tener a la vez una fila en `human_approvals` y otra en `human_approval_expirations`. Esto se verifica en la transacción con la fila del journal bloqueada.
- Hay que definir si es reversible; la nota 06 señala que hoy las migraciones no lo son.

## 7. Validación (decisión 4; revisada por el CTO, 29-oct-2026)

- `Policy.max_approval_ms: Option<u64>` acota el plazo de aprobación. Una solicitud cuyo plazo pedido es mayor se rechaza.
- Las reglas declaran opcionalmente `control_loop: fast | slow` y `delta_ms`.
- Errores al cargar la política:
  - Una regla `RequireApproval` con `control_loop = fast` a la que le falte `max_approval_ms` o `delta_ms` (fail-closed, CTO 29-oct-2026). En el lazo rápido solo se acepta si existen ambos y `delta_ms ≥ max_approval_ms`.
  - Una regla `RequireApproval` con `delta_ms < max_approval_ms`.
  - Una regla `Deny` o `RequireApproval` sobre una acción `safety:*`. Esto queda como **aviso** si se mantiene el lint externo de SAF-09.
- La validación no prueba tiempos reales. Solo verifica que lo declarado sea coherente.

## 8. Tests de propiedad (van primero, decisión 5)

1. **Endurecimiento:** para toda política y regla adicional `x`, `sev(eval(P + x)) ≥ sev(eval(P))`.
2. **Deny gana en admisión:** si alguna regla que coincide da Deny, entonces `outcome == Deny` y no hay despacho.
3. **Recover no se suprime:** si alguna regla que coincide es Recover, entonces `recovery.is_some()` aunque otra regla niegue.
4. **Recover nunca despacha:** `recovery.is_some()` implica `ExecutionStatus::NotDispatched` y cero invocaciones del adaptador, aunque exista la attestation de negación.
5. **No hay aprobación por silencio:** para toda traza sin decisión humana firmada en la que `now > expires_at`, no hay despacho y existe exactamente un `ApprovalExpiredReceipt` válido.
6. **Exclusión:** nunca coexisten una decisión humana y un vencimiento para la misma clave.
7. **Álgebra de la combinación de reglas:** `strongest` es asociativa e idempotente y conmutativa en `outcome`; el orden de las reglas no cambia el outcome.
8. **Compatibilidad:** la evidencia v2 existente verifica sin cambios, y el digest de una política sin campos nuevos es el mismo que en main (vector fijo).
9. **Validación:** se rechaza `RequireApproval` con `control_loop = fast` si falta `max_approval_ms` o `delta_ms`, y en cualquier lazo si `delta_ms < max_approval_ms`.

## 9. Pendientes

- **WCET del motor: NO medido.** Ningún plazo de esta propuesta supone un WCET.
- **Tiempo de respuesta humana: sin datos.** No hay base para fijar `T_approval` en contextos físicos.
- Catálogo de `recovery_id` (agentes de software y un programa piloto) y su semántica de salida y reingreso.
- Número definitivo de la propuesta y de la migración, y si la migración es reversible.
- ASTM F3269-21 (§5.8, §5.9, §5.4.3.8 y Apéndice X5) no se leyó por paywall.

## Decisión del CTO sobre la migración 0009 (29-oct-2026)

- La 0009 es **forward-only**. Es evidencia append-only, así que no lleva un `down` que borre datos.
- Si hay que revertirla, se hace con una **migración compensatoria** que deshabilite la escritura y no toque los datos ya guardados.
- Número SAF-10 confirmado por el CTO. La implementación queda a cargo del Especialista PRÆTORE (Rust).

## Notas de revisión contra a797bea

Revisión de solo lectura de la propuesta contra `origin/main` `a797bea` (29-oct-2026). No cambia ninguna decisión de §1 ni la decisión del CTO sobre la 0009. Los puntos marcados **[decisión]** requieren al CTO.

Confirmado:
- `DecisionOutcome` tiene tres valores y `strongest` aplica Deny > RequireApproval > Allow (`decision.rs:17-33`).
- `ApprovalResolution {Pending, Approved, Rejected, Expired}` (`gateway/src/lib.rs:180-185`), plazo `min(intent.expires_at, freshness_valid_until)` (`:137-147`), `approval_resolution` calcula `Expired` (`:825-852`), `validate_approval_time_bounds` mapea a `ApprovalError::Expired` (`:941-951`), error en `:288`.
- HTTP 410 `approval_expired` (`http_api.rs:197,215,284`); CLI `Expired` (`cli/src/main.rs:1365-1381`); test `enforcement.rs:1127`; `docs/assurance-matrix.md:23`.
- Migraciones `0001`–`0008` en `crates/praetore-replay-postgres/migrations/`. La siguiente libre es `0009`: ninguna rama remota de `origin` tiene un archivo `migrations/0009*`.
- `0006` admite solo `outcome IN ('approve','reject')`; `0004` solo registra transiciones de `execution_status`.
- `Decision`, `DecisionContribution`, `Evidence` y `PolicyRule` usan `deny_unknown_fields`.

Discrepancias:
1. **RESUELTA por el CTO (29-oct-2026): sin compose ni capas; una sola Policy, piso × tenant queda como trabajo futuro (§3, §4, §8).** ~~No existe composición piso × tenant.** En `a797bea` hay una sola `Policy` por motor (`Policy::evaluate_with_context` combina reglas con `Decision::strongest`). No hay tipos `Floor`/`Tenant`, ni `compose`, ni dos capas de política. §3, §4 y los tests 1, 3 y 7 suponen una capa de piso que no existe; falta decidir dónde vive (motor, gateway o configuración) y cómo se carga.~~
2. **RESUELTA por el CTO: `Policy.max_approval_ms: Option<u64>` (§7).** ~~No existe `T_approval_ms` como valor configurable.** El plazo de aprobación se deriva por solicitud de `intent.expires_at` y `freshness_valid_until`; no se conoce al cargar la política. La validación de §7 (`delta_ms < T_approval_ms`, test 9) necesita una cota estática que hoy no existe.~~
3. **RESUELTA por el CTO: el campo se llama `control_loop`; campos nuevos opcionales con `skip_serializing_if`, sin subir versión, con test de vector fijo del digest.** ~~`loop` es palabra reservada en Rust.~~ El campo de regla `loop: fast | slow` requiere otro nombre en Rust (p. ej. `r#loop` o `loop_kind` con `#[serde(rename = "loop")]`). Como `PolicyRule` usa `deny_unknown_fields` y entra en `Policy::digest`, agregar `loop`/`delta_ms` cambia el formato de política: hay que decidir si sube `canonical_version`/`semantics_version` o si los campos son opcionales y omitidos al serializar (para no cambiar el digest de políticas existentes). **[decisión]**
4. **Versionado de evidencia.** La evidencia actual es `evidence_schema_version` 1 o 2 (`evidence.rs:184-187`; `engine.rs:697,748` exigen 2 en HighAssurance). Agregar `recovery` a `Decision` (con `deny_unknown_fields`) implica v3 y cambios en `has_v2_fields`/`has_complete_v2_fields` y en las comprobaciones de `engine.rs`. Consistente con §3; se anota la ubicación.
5. **No hay fixture de evidencia v2 en el repo.** `docs/golden/` contiene `agent-key-fingerprint-v1`, `canonical-policy-v1` y `trust-chain-v1`; no hay evidencia v2 congelada. El test 8 ("la evidencia v2 existente verifica sin cambios") hoy solo puede ejercitarse con evidencia v2 generada en el test, no con un vector dorado. Conviene agregar `docs/golden/evidence-v2.json` antes del paso 3.
6. **`safety:*` no existe en el código.** No hay acciones `safety:` ni el lint de SAF-09 en `a797bea`; el aviso de §7 depende de SAF-09.
7. **RESUELTA por el CTO: test 4 = "NotDispatched y cero invocaciones", aunque exista la attestation de negación.** ~~"Recibo de ejecución" (test 4)~~ corresponde hoy a `ExecutionAttestation`/`GatewayReceipt` (`gateway/src/lib.rs:321,562`); el gateway emite una attestation firmada también para Deny/NotDispatched. El test 4 debe formularse como "no hay despacho (`ExecutionStatus::NotDispatched`, cero invocaciones del adaptador)", no como "no existe recibo". **[decisión menor de redacción]**
8. **Lazo rápido.** No existe noción de lazo rápido/lento en el código; RequireApproval hoy siempre pasa por el journal y por aprobación humana asíncrona. La decisión 4 se apoya íntegramente en la declaración nueva de §7.
9. Orden de variantes: `PolicyEffect` es `{Allow, Deny, RequireApproval}` (`policy.rs:925`), no `{Allow, Deny, RequireApproval, Recover}` en otro orden; sin efecto semántico, se anota.
10. **RESUELTA por el CTO: el archivo se llama `SAF-10-RECOVER-Y-VENCIMIENTO-DE-APROBACIONES.md`.** ~~Nombre del archivo: SAF-09 usa `SAF-09-…` en mayúsculas; esta copia usa kebab-case en minúsculas por instrucción. Unificar si se prefiere. **[decisión menor]**~~


## Implementación (rama `feat/saf10-recover`, decisiones del CTO del 29-oct-2026)

- **Varios Recover que coinciden:** gana el primero en el orden de reglas de la política. Su `RecoveryObligation` (con su `rule_id`) es la que queda en la decisión; las demás se descartan y el outcome es Deny. Lo prueba `full::first_matching_recover_rule_wins` en `crates/praetore-core/tests/saf10_properties.rs`. El orden de las reglas no cambia el outcome ni la existencia de una obligación (`p7_rule_order_with_recover`).
- **Lazo rápido (fail-closed):** `RequireApproval` con `control_loop = fast` se carga solo si existen `max_approval_ms` y `delta_ms` y `delta_ms ≥ max_approval_ms`. Si falta cualquiera de los dos, es error de carga.
- **Plazo pedido mayor que `max_approval_ms`:** el motor responde `IntentInvalid` antes del replay claim.
- **Receipt de vencimiento:** `ApprovalExpiredReceipt` lleva `receipt_id` (UUID v4, firmado). La respuesta HTTP 410 `approval_expired` incluye `expiration_receipt_id`.
- **Migración 0009:** forward-only y append-only, con RLS por tenant. La referencia a `execution_journal` se hace con triggers en vez de FK, porque 0007 se reaplica en cada arranque y recrea `execution_journal_pkey`. Borrar una fila del journal que tiene un receipt queda bloqueado (semántica ON DELETE RESTRICT). 0007 no se modifica.

### Limitación conocida

- Los checks previos a la política niegan **sin evaluar las reglas Recover**. Si la autoridad no permite la capacidad pedida, la decisión es Deny sin `recovery`, aunque la política tenga una regla Recover que habría coincidido. Los fallos de identidad, intención, frescura o reloj rechazan la solicitud con error antes de evaluar la política y tampoco producen obligación. No hay paso a modo seguro por esas vías.
