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

## 3. Cambios de tipos propuestos (pseudocódigo, sin implementar)

```text
// praetore-core (sin cambios en el enum)
enum DecisionOutcome { Allow, RequireApproval, Deny }

struct RecoveryObligation {
    recovery_id: String,        // modo seguro predeclarado en el piso o el tenant
    source_layer: Floor | Tenant,
    rule_id: String,
    reason: String,
    deadline: Duration,         // T_recover_max, acotado
}

struct Decision {
    outcome: DecisionOutcome,
    reason: String,
    contributions: Vec<DecisionContribution>,
    recovery: Option<RecoveryObligation>,   // nuevo
}
// Invariante: recovery.is_some()  =>  outcome != Allow
// Severidad efectiva: sev(d) = Recover si recovery.is_some(), si no, outcome
//                     Recover > Deny > RequireApproval > Allow

enum PolicyEffect { Allow, Deny, RequireApproval, Recover { recovery_id, deadline } }
// Recover como efecto de regla produce outcome = Deny + recovery = Some(..)

// Composición
fn compose(floor: Decision, tenant: Decision) -> Decision {
    outcome  = strongest(floor.outcome, tenant.outcome)   // deny gana en admisión
    recovery = floor.recovery.or(tenant.recovery)          // la del piso gana; nunca se descarta
    if recovery.is_some() && outcome == Allow { outcome = Deny }
}

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

- Compatibilidad: `Decision` y `Evidence` usan `deny_unknown_fields`. El campo `recovery` exige subir la versión del schema de evidencia, y la evidencia v2 sin `recovery` tiene que seguir verificando.

## 4. Composición piso × tenant

| piso \ tenant | Allow | RequireApproval | Deny | Recover |
|---|---|---|---|---|
| Allow | Allow | RequireApproval | Deny | Deny + recovery(tenant) |
| RequireApproval | RequireApproval | RequireApproval | Deny | Deny + recovery(tenant) |
| Deny | Deny | Deny | Deny | Deny + recovery(tenant) |
| Recover | Deny + recovery(piso) | Deny + recovery(piso) | Deny + recovery(piso) | Deny + recovery(piso) |

- La admisión de la acción propuesta sigue `strongest`, de modo que deny gana.
- La obligación de recuperación del piso **no se descarta** por un Deny de otra capa (decisión 2, alternativa A). Es una divergencia deliberada con XACML 3.0 §7.18, que descarta las obligaciones de la rama perdedora.
- El tenant puede agregar una recuperación, pero no puede quitar ni reemplazar la del piso.

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

## 7. Validación (decisión 4)

- Las reglas declaran `loop: fast | slow` (por defecto `slow`) y, opcionalmente, `delta_ms`.
- Errores al cargar la política:
  - Una regla `RequireApproval` con `loop: fast`.
  - Una regla `RequireApproval` con `delta_ms < T_approval_ms`.
  - Una regla `Deny` o `RequireApproval` sobre una acción `safety:*`. Esto queda como **aviso** si se mantiene el lint externo de SAF-09.
- La validación no prueba tiempos reales. Solo verifica que lo declarado sea coherente.

## 8. Tests de propiedad (van primero, decisión 5)

1. **Endurecimiento:** para todo `r`, piso y `T`, `sev(compose(piso,T)(r)) ≥ sev(piso(r))`.
2. **Deny gana en admisión:** si alguna capa da Deny, entonces `outcome == Deny` y no hay despacho.
3. **Recover del piso no se suprime:** si `piso(r).recovery == Some(x)`, entonces `compose(piso,T)(r).recovery == Some(x)` para todo `T`.
4. **Recover nunca despacha:** `recovery.is_some()` implica que no existe ningún recibo de ejecución de `action_digest`.
5. **No hay aprobación por silencio:** para toda traza sin decisión humana firmada en la que `now > expires_at`, no hay despacho y existe exactamente un `ApprovalExpiredReceipt` válido.
6. **Exclusión:** nunca coexisten una decisión humana y un vencimiento para la misma clave.
7. **Álgebra de `compose`:** asociativa e idempotente, y conmutativa en `outcome`.
8. **Compatibilidad:** la evidencia v2 existente verifica sin cambios.
9. **Validación:** se rechaza `RequireApproval` con `loop: fast` o con `delta_ms < T_approval_ms`.

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
1. **[decisión] No existe composición piso × tenant.** En `a797bea` hay una sola `Policy` por motor (`Policy::evaluate_with_context` combina reglas con `Decision::strongest`). No hay tipos `Floor`/`Tenant`, ni `compose`, ni dos capas de política. §3, §4 y los tests 1, 3 y 7 suponen una capa de piso que no existe; falta decidir dónde vive (motor, gateway o configuración) y cómo se carga.
2. **[decisión] No existe `T_approval_ms` como valor configurable.** El plazo de aprobación se deriva por solicitud de `intent.expires_at` y `freshness_valid_until`; no se conoce al cargar la política. La validación de §7 (`delta_ms < T_approval_ms`, test 9) necesita una cota estática que hoy no existe.
3. **`loop` es palabra reservada en Rust.** El campo de regla `loop: fast | slow` requiere otro nombre en Rust (p. ej. `r#loop` o `loop_kind` con `#[serde(rename = "loop")]`). Como `PolicyRule` usa `deny_unknown_fields` y entra en `Policy::digest`, agregar `loop`/`delta_ms` cambia el formato de política: hay que decidir si sube `canonical_version`/`semantics_version` o si los campos son opcionales y omitidos al serializar (para no cambiar el digest de políticas existentes). **[decisión]**
4. **Versionado de evidencia.** La evidencia actual es `evidence_schema_version` 1 o 2 (`evidence.rs:184-187`; `engine.rs:697,748` exigen 2 en HighAssurance). Agregar `recovery` a `Decision` (con `deny_unknown_fields`) implica v3 y cambios en `has_v2_fields`/`has_complete_v2_fields` y en las comprobaciones de `engine.rs`. Consistente con §3; se anota la ubicación.
5. **No hay fixture de evidencia v2 en el repo.** `docs/golden/` contiene `agent-key-fingerprint-v1`, `canonical-policy-v1` y `trust-chain-v1`; no hay evidencia v2 congelada. El test 8 ("la evidencia v2 existente verifica sin cambios") hoy solo puede ejercitarse con evidencia v2 generada en el test, no con un vector dorado. Conviene agregar `docs/golden/evidence-v2.json` antes del paso 3.
6. **`safety:*` no existe en el código.** No hay acciones `safety:` ni el lint de SAF-09 en `a797bea`; el aviso de §7 depende de SAF-09.
7. **"Recibo de ejecución" (test 4)** corresponde hoy a `ExecutionAttestation`/`GatewayReceipt` (`gateway/src/lib.rs:321,562`); el gateway emite una attestation firmada también para Deny/NotDispatched. El test 4 debe formularse como "no hay despacho (`ExecutionStatus::NotDispatched`, cero invocaciones del adaptador)", no como "no existe recibo". **[decisión menor de redacción]**
8. **Lazo rápido.** No existe noción de lazo rápido/lento en el código; RequireApproval hoy siempre pasa por el journal y por aprobación humana asíncrona. La decisión 4 se apoya íntegramente en la declaración nueva de §7.
9. Orden de variantes: `PolicyEffect` es `{Allow, Deny, RequireApproval}` (`policy.rs:925`), no `{Allow, Deny, RequireApproval, Recover}` en otro orden; sin efecto semántico, se anota.
10. Nombre del archivo: SAF-09 usa `SAF-09-…` en mayúsculas; esta copia usa kebab-case en minúsculas por instrucción. Unificar si se prefiere. **[decisión menor]**
